use anyhow::{bail, Context, Result};
use base64::Engine as _;
use corvid_abi::{
    descriptor_from_embedded_section, read_embedded_section_from_library, AbiAgent, ScalarTypeName,
    TypeDescription,
};
use corvid_bind::{generate_bindings_from_descriptor_path, BindLanguage};
use corvid_driver::{build_catalog_descriptor_for_source, build_target_to_disk, BuildTarget};
use corvid_trace_schema::{read_events_from_path, validate_supported_schema, TraceEvent};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::ffi::{c_char, CString};
use std::fs;
use std::path::Path;

use super::manifest::{
    compare_dirs, compare_paths, current_target_triple, sha256_dir, sha256_file, LoadedManifest,
};

pub fn run_verify(bundle: &Path, rebuild: bool) -> Result<u8> {
    let loaded = LoadedManifest::load(bundle)?;
    verify_committed(&loaded)?;
    if rebuild {
        verify_rebuild(&loaded)?;
    }
    println!(
        "bundle OK: {} ({})",
        loaded.manifest.name, loaded.manifest.target_triple
    );
    Ok(0)
}

fn verify_committed(loaded: &LoadedManifest) -> Result<()> {
    verify_hash(
        "library",
        &loaded.library_path(),
        &loaded.manifest.hashes.library,
        false,
    )?;
    verify_hash(
        "descriptor",
        &loaded.descriptor_path(),
        &loaded.manifest.hashes.descriptor,
        false,
    )?;
    if let (Some(path), Some(expected)) = (loaded.header_path(), loaded.manifest.hashes.header.as_deref()) {
        verify_hash("header", &path, expected, false)?;
    }
    if let (Some(path), Some(expected)) = (
        loaded.tools_staticlib_path(),
        loaded.manifest.hashes.tools_staticlib.as_deref(),
    ) {
        verify_hash("tools_staticlib", &path, expected, false)?;
    }
    verify_hash(
        "bindings_rust",
        &loaded.bindings_rust_dir(),
        &loaded.manifest.hashes.bindings_rust,
        true,
    )?;
    verify_hash(
        "bindings_python",
        &loaded.bindings_python_dir(),
        &loaded.manifest.hashes.bindings_python,
        true,
    )?;
    if let (Some(path), Some(expected)) = (
        loaded.capsule_path(),
        loaded.manifest.hashes.capsule.as_deref(),
    ) {
        verify_hash("capsule", &path, expected, false)?;
    }
    if let (Some(path), Some(expected)) = (
        loaded.receipt_envelope_path(),
        loaded.manifest.hashes.receipt_envelope.as_deref(),
    ) {
        verify_hash("receipt_envelope", &path, expected, false)?;
    }
    if let (Some(path), Some(expected)) = (
        loaded.receipt_verify_key_path(),
        loaded.manifest.hashes.receipt_verify_key.as_deref(),
    ) {
        verify_hash("receipt_verify_key", &path, expected, false)?;
    }
    for trace in &loaded.manifest.traces {
        verify_hash(
            &format!("trace `{}`", trace.name),
            &loaded.resolve(&trace.path),
            &trace.sha256,
            false,
        )?;
        let events = read_events_from_path(&loaded.resolve(&trace.path))
            .with_context(|| format!("read trace `{}`", loaded.resolve(&trace.path).display()))?;
        validate_supported_schema(&events)
            .with_context(|| format!("validate trace `{}`", loaded.resolve(&trace.path).display()))?;
        let (agent, _args) = last_run_started(&events)?;
        if agent != trace.expected_agent {
            bail!(
                "BundleTraceAgentMismatch: trace `{}` recorded `{}` but manifest expected `{}`",
                trace.name,
                agent,
                trace.expected_agent
            );
        }
    }

    if let (Some(envelope_path), Some(key_path)) = (
        loaded.receipt_envelope_path(),
        loaded.receipt_verify_key_path(),
    ) {
        verify_dsse_envelope(&envelope_path, &key_path)?;
    }

    Ok(())
}

fn verify_rebuild(loaded: &LoadedManifest) -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!(
            "BundlePlatformUnsupported: strict --rebuild verification is only supported on Linux in v1; host `{}` cannot rebuild bundle target `{}` byte-identically",
            current_target_triple(),
            loaded.manifest.target_triple
        );
    }

    if loaded.manifest.target_triple != current_target_triple() {
        bail!(
            "BundlePlatformUnsupported: bundle target `{}` cannot be rebuilt on host `{}`",
            loaded.manifest.target_triple,
            current_target_triple()
        );
    }

    let abi_output = build_catalog_descriptor_for_source(&loaded.primary_source_path())
        .with_context(|| format!("rebuild descriptor from `{}`", loaded.primary_source_path().display()))?;
    if !abi_output.diagnostics.is_empty() {
        let first = &abi_output.diagnostics[0];
        bail!(
            "BundleRebuildFailed: descriptor rebuild surfaced {} diagnostic(s); first: {}",
            abi_output.diagnostics.len(),
            first
        );
    }
    let rebuilt_descriptor = abi_output
        .descriptor_json
        .ok_or_else(|| anyhow::anyhow!("BundleRebuildFailed: descriptor rebuild produced no JSON"))?;
    let expected_descriptor = fs::read(loaded.descriptor_path())
        .with_context(|| format!("read descriptor `{}`", loaded.descriptor_path().display()))?;
    super::manifest::compare_bytes(
        "descriptor",
        &expected_descriptor,
        rebuilt_descriptor.as_bytes(),
    )?;

    let tools_staticlib = loaded.tools_staticlib_path();
    let tool_refs: Vec<&Path> = tools_staticlib.iter().map(|path| path.as_path()).collect();
    let build_output = build_target_to_disk(
        &loaded.primary_source_path(),
        BuildTarget::Cdylib,
        loaded.header_path().is_some(),
        true,
        &tool_refs,
    )
    .with_context(|| format!("rebuild cdylib from `{}`", loaded.primary_source_path().display()))?;
    if !build_output.diagnostics.is_empty() {
        let first = &build_output.diagnostics[0];
        bail!(
            "BundleRebuildFailed: library rebuild surfaced {} diagnostic(s); first: {}",
            build_output.diagnostics.len(),
            first
        );
    }
    let rebuilt_library = build_output
        .output_path
        .ok_or_else(|| anyhow::anyhow!("BundleRebuildFailed: library rebuild produced no output"))?;
    compare_paths("library", &loaded.library_path(), &rebuilt_library)?;
    if let (Some(expected_header), Some(rebuilt_header)) = (loaded.header_path(), build_output.header_path) {
        compare_paths("header", &expected_header, &rebuilt_header)?;
    }

    let temp = tempfile::tempdir().context("create bundle rebuild tempdir")?;
    let rebuilt_descriptor_path = temp.path().join(
        loaded
            .descriptor_path()
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("descriptor path had no filename"))?,
    );
    fs::write(&rebuilt_descriptor_path, rebuilt_descriptor).context("write rebuilt descriptor")?;

    let rebuilt_rust_dir = temp.path().join("bindings_rust");
    generate_bindings_from_descriptor_path(BindLanguage::Rust, &rebuilt_descriptor_path, &rebuilt_rust_dir)
        .context("rebuild Rust bindings")?;
    compare_dirs("bindings_rust", &loaded.bindings_rust_dir(), &rebuilt_rust_dir)?;

    let rebuilt_python_dir = temp.path().join("bindings_python");
    generate_bindings_from_descriptor_path(
        BindLanguage::Python,
        &rebuilt_descriptor_path,
        &rebuilt_python_dir,
    )
    .context("rebuild Python bindings")?;
    compare_dirs("bindings_python", &loaded.bindings_python_dir(), &rebuilt_python_dir)?;

    for trace in &loaded.manifest.traces {
        let result = unsafe { replay_library_trace(&rebuilt_library, &loaded.resolve(&trace.path)) }?;
        if result.agent != trace.expected_agent {
            bail!(
                "BundleReplayMismatch: trace `{}` replayed agent `{}` instead of `{}`",
                trace.name,
                result.agent,
                trace.expected_agent
            );
        }
        if result.result_json != trace.expected_result_json {
            bail!(
                "BundleReplayMismatch: trace `{}` result diverged (expected {}, got {})",
                trace.name,
                trace.expected_result_json,
                result.result_json
            );
        }
        if let Some(expected_observation) = trace.expected_observation {
            if result.observation_present != expected_observation {
                bail!(
                    "BundleReplayMismatch: trace `{}` observation presence diverged (expected {}, got {})",
                    trace.name,
                    expected_observation,
                    result.observation_present
                );
            }
        }
        if result.grounded_sources != trace.expected_grounded_sources {
            bail!(
                "BundleReplayMismatch: trace `{}` grounded sources diverged (expected {:?}, got {:?})",
                trace.name,
                trace.expected_grounded_sources,
                result.grounded_sources
            );
        }
    }

    Ok(())
}

fn verify_hash(label: &str, path: &Path, expected: &str, is_dir: bool) -> Result<()> {
    let actual = if is_dir {
        sha256_dir(path)?
    } else {
        sha256_file(path)?
    };
    if actual != expected {
        bail!(
            "BundleHashMismatch: {label} expected {} but found {} for `{}`",
            expected,
            actual,
            path.display()
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    signatures: Vec<DsseSignature>,
}

#[derive(Debug, Deserialize)]
struct DsseSignature {
    #[allow(dead_code)]
    keyid: String,
    sig: String,
}

fn verify_dsse_envelope(envelope_path: &Path, key_path: &Path) -> Result<()> {
    let envelope_bytes = fs::read(envelope_path)
        .with_context(|| format!("read receipt envelope `{}`", envelope_path.display()))?;
    let envelope: DsseEnvelope = serde_json::from_slice(&envelope_bytes)
        .with_context(|| format!("parse receipt envelope `{}`", envelope_path.display()))?;
    if envelope.signatures.is_empty() {
        bail!(
            "BundleSignatureVerifyFailed: `{}` contains no signatures",
            envelope_path.display()
        );
    }

    let key = load_verifying_key(key_path)?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(envelope.payload.as_bytes())
        .context("decode envelope payload")?;
    let pae = pae(&envelope.payload_type, &payload);
    let mut any_valid = false;
    for signature in &envelope.signatures {
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature.sig.as_bytes())
            .context("decode envelope signature")?;
        if sig_bytes.len() != 64 {
            continue;
        }
        let sig = Signature::from_bytes(
            &sig_bytes
                .as_slice()
                .try_into()
                .expect("length checked above"),
        );
        if key.verify(&pae, &sig).is_ok() {
            any_valid = true;
            break;
        }
    }
    if !any_valid {
        bail!(
            "BundleSignatureVerifyFailed: `{}` did not verify against `{}`",
            envelope_path.display(),
            key_path.display()
        );
    }
    Ok(())
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let raw = fs::read(path).with_context(|| format!("read verifying key `{}`", path.display()))?;
    let trimmed = raw
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<u8>>();
    let bytes: [u8; 32] = if trimmed.iter().all(|byte| byte.is_ascii_hexdigit()) && trimmed.len() == 64 {
        let mut out = [0u8; 32];
        hex::decode_to_slice(&trimmed, &mut out).context("hex decode verifying key")?;
        out
    } else if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    } else {
        bail!(
            "BundleSignatureVerifyFailed: `{}` is not a 32-byte ed25519 verifying key",
            path.display()
        );
    };
    VerifyingKey::from_bytes(&bytes).context("parse verifying key")
}

fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

#[repr(C)]
#[derive(Default)]
struct CorvidApprovalRequired {
    site_name: *const c_char,
    predicate_json: *const c_char,
    args_json: *const c_char,
    rationale_prompt: *const c_char,
}

type CorvidCallAgentFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    usize,
    *mut *mut c_char,
    *mut usize,
    *mut u64,
    *mut CorvidApprovalRequired,
) -> u32;

type CorvidFreeResultFn = unsafe extern "C" fn(*mut c_char);
type CorvidFreeStringFn = unsafe extern "C" fn(*const c_char);
type CorvidObservationReleaseFn = unsafe extern "C" fn(u64);
type CorvidGroundedSourcesFn = unsafe extern "C" fn(u64, *mut *const c_char, usize) -> i32;
type CorvidGroundedReleaseFn = unsafe extern "C" fn(u64);

struct ReplayOutput {
    agent: String,
    result_json: String,
    observation_present: bool,
    grounded_sources: Vec<String>,
}

unsafe fn replay_library_trace(library_path: &Path, trace_path: &Path) -> Result<ReplayOutput> {
    let events = read_events_from_path(trace_path)
        .with_context(|| format!("read trace `{}`", trace_path.display()))?;
    validate_supported_schema(&events)
        .with_context(|| format!("validate trace `{}`", trace_path.display()))?;
    let (agent, args) = last_run_started(&events)?;
    let deterministic_seed = derive_deterministic_seed(&events);
    let replay_model = last_recorded_model(&events);

    let deterministic_seed_string = deterministic_seed.to_string();
    let trace_guard = EnvGuard::set(&[
        ("CORVID_REPLAY_TRACE_PATH", Some(trace_path.as_os_str())),
        ("CORVID_TRACE_DISABLE", Some(std::ffi::OsStr::new("1"))),
        (
            "CORVID_DETERMINISTIC_SEED",
            Some(std::ffi::OsStr::new(&deterministic_seed_string)),
        ),
    ]);
    let model_guard = replay_model.as_deref().map(|model| {
        EnvGuard::set(&[("CORVID_MODEL", Some(std::ffi::OsStr::new(model)))])
    });

    let library = libloading::Library::new(library_path)
        .with_context(|| format!("load rebuilt library `{}`", library_path.display()))?;
    let agent_abi = load_agent_abi(library_path, &agent)?;
    let call_agent: libloading::Symbol<CorvidCallAgentFn> = library
        .get(b"corvid_call_agent")
        .context("resolve corvid_call_agent")?;
    let free_result: libloading::Symbol<CorvidFreeResultFn> = library
        .get(b"corvid_free_result")
        .context("resolve corvid_free_result")?;
    let observation_release: Option<libloading::Symbol<CorvidObservationReleaseFn>> =
        library.get(b"corvid_observation_release").ok();

    let args_json = serde_json::Value::Array(args.clone()).to_string();
    let agent_c = CString::new(agent.clone()).context("agent name contained NUL")?;
    let args_c = CString::new(args_json).context("args JSON contained NUL")?;
    let mut result_ptr: *mut c_char = std::ptr::null_mut();
    let mut result_len = 0usize;
    let mut observation_handle = 0u64;
    let mut approval = CorvidApprovalRequired::default();
    let status = call_agent(
        agent_c.as_ptr(),
        args_c.as_ptr(),
        args_c.as_bytes().len(),
        &mut result_ptr,
        &mut result_len,
        &mut observation_handle,
        &mut approval,
    );
    if status == 3 {
        if let Some(abi) = agent_abi.as_ref() {
            if matches_grounded_string_signature(abi) {
                drop(model_guard);
                drop(trace_guard);
                let direct_trace_guard = EnvGuard::set(&[
                    ("CORVID_REPLAY_TRACE_PATH", Some(trace_path.as_os_str())),
                    ("CORVID_TRACE_DISABLE", Some(std::ffi::OsStr::new("1"))),
                    (
                        "CORVID_DETERMINISTIC_SEED",
                        Some(std::ffi::OsStr::new(&deterministic_seed_string)),
                    ),
                ]);
                let direct_model_guard = replay_model.as_deref().map(|model| {
                    EnvGuard::set(&[("CORVID_MODEL", Some(std::ffi::OsStr::new(model)))])
                });
                let output = replay_grounded_string_direct(&library, abi, &args)?;
                drop(direct_model_guard);
                drop(direct_trace_guard);
                return Ok(output);
            }
        }
    }
    if status != 0 {
        bail!(
            "BundleReplayMismatch: replayed library returned status {} for trace `{}`",
            status,
            trace_path.display()
        );
    }
    let result_json = if !result_ptr.is_null() {
        let bytes = std::slice::from_raw_parts(result_ptr as *const u8, result_len);
        let text = String::from_utf8_lossy(bytes).into_owned();
        free_result(result_ptr);
        text
    } else {
        "null".to_string()
    };
    if let Some(release) = observation_release {
        if observation_handle != 0 {
            release(observation_handle);
        }
    }
    drop(model_guard);
    drop(trace_guard);

    Ok(ReplayOutput {
        agent,
        result_json,
        observation_present: observation_handle != 0,
        grounded_sources: Vec::new(),
    })
}

fn load_agent_abi(library_path: &Path, agent_name: &str) -> Result<Option<AbiAgent>> {
    let section = read_embedded_section_from_library(library_path)
        .with_context(|| format!("read embedded descriptor from `{}`", library_path.display()))?;
    let descriptor = descriptor_from_embedded_section(&section)
        .context("decode embedded descriptor")?;
    Ok(descriptor
        .agents
        .into_iter()
        .find(|agent| agent.name == agent_name))
}

fn matches_grounded_string_signature(agent: &AbiAgent) -> bool {
    if agent.params.len() != 1 {
        return false;
    }
    matches!(
        &agent.params[0].ty,
        TypeDescription::Scalar {
            scalar: ScalarTypeName::String
        }
    ) && matches!(
        &agent.return_type,
        TypeDescription::Grounded { grounded }
            if matches!(
                grounded.inner.as_ref(),
                TypeDescription::Scalar {
                    scalar: ScalarTypeName::String
                }
            )
    )
}

unsafe fn replay_grounded_string_direct(
    library: &libloading::Library,
    agent: &AbiAgent,
    args: &[serde_json::Value],
) -> Result<ReplayOutput> {
    let [arg0] = args else {
        bail!(
            "BundleReplayUnsupported: grounded direct replay for `{}` expected one argument, got {}",
            agent.name,
            args.len()
        );
    };
    let arg0 = arg0
        .as_str()
        .ok_or_else(|| anyhow::anyhow!(
            "BundleReplayUnsupported: grounded direct replay for `{}` expects one String argument",
            agent.name
        ))?;
    let symbol_name = agent.symbol.as_bytes();
    let grounded_fn: libloading::Symbol<
        unsafe extern "C" fn(*const c_char, *mut u64, *mut u64) -> *const c_char,
    > = library
        .get(symbol_name)
        .with_context(|| format!("resolve grounded export `{}`", agent.symbol))?;
    let free_string: libloading::Symbol<CorvidFreeStringFn> = library
        .get(b"corvid_free_string")
        .context("resolve corvid_free_string")?;
    let grounded_sources: libloading::Symbol<CorvidGroundedSourcesFn> = library
        .get(b"corvid_grounded_sources")
        .context("resolve corvid_grounded_sources")?;
    let grounded_release: libloading::Symbol<CorvidGroundedReleaseFn> = library
        .get(b"corvid_grounded_release")
        .context("resolve corvid_grounded_release")?;
    let observation_release: Option<libloading::Symbol<CorvidObservationReleaseFn>> =
        library.get(b"corvid_observation_release").ok();

    let arg0_c = CString::new(arg0).context("grounded replay arg contained NUL")?;
    let mut grounded_handle = 0u64;
    let mut observation_handle = 0u64;
    let value_ptr = grounded_fn(
        arg0_c.as_ptr(),
        &mut grounded_handle,
        &mut observation_handle,
    );
    if value_ptr.is_null() {
        bail!(
            "BundleReplayMismatch: grounded export `{}` returned null String pointer",
            agent.name
        );
    }
    let value = std::ffi::CStr::from_ptr(value_ptr)
        .to_str()
        .context("grounded replay result was not UTF-8")?
        .to_owned();
    let grounded_sources_list = read_grounded_sources(&*grounded_sources, grounded_handle)?;
    if let Some(release) = observation_release {
        if observation_handle != 0 {
            release(observation_handle);
        }
    }
    if grounded_handle != 0 {
        grounded_release(grounded_handle);
    }
    free_string(value_ptr);

    Ok(ReplayOutput {
        agent: agent.name.clone(),
        result_json: serde_json::to_string(&value).context("serialize grounded replay result")?,
        observation_present: observation_handle != 0,
        grounded_sources: grounded_sources_list,
    })
}

unsafe fn read_grounded_sources(
    grounded_sources: &CorvidGroundedSourcesFn,
    handle: u64,
) -> Result<Vec<String>> {
    if handle == 0 {
        return Ok(Vec::new());
    }
    let count = grounded_sources(handle, std::ptr::null_mut(), 0);
    if count < 0 {
        bail!("BundleReplayMismatch: grounded handle {handle} exposed no sources");
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut ptrs = vec![std::ptr::null(); count as usize];
    let filled = grounded_sources(handle, ptrs.as_mut_ptr(), ptrs.len());
    if filled != count {
        bail!(
            "BundleReplayMismatch: grounded sources count changed during read ({} -> {})",
            count,
            filled
        );
    }
    let mut out = Vec::with_capacity(ptrs.len());
    for ptr in ptrs {
        if ptr.is_null() {
            bail!("BundleReplayMismatch: grounded source pointer was null");
        }
        out.push(
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .context("grounded source was not UTF-8")?
                .to_owned(),
        );
    }
    Ok(out)
}

fn last_run_started(events: &[TraceEvent]) -> Result<(String, Vec<serde_json::Value>)> {
    events
        .iter()
        .find_map(|event| match event {
            TraceEvent::RunStarted { agent, args, .. } => Some((agent.clone(), args.clone())),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("trace had no run_started event"))
}

fn derive_deterministic_seed(events: &[TraceEvent]) -> u64 {
    events
        .iter()
        .rev()
        .find_map(|event| match event {
            TraceEvent::SeedRead { purpose, value, .. } if purpose == "rollout_default_seed" => {
                Some(*value)
            }
            _ => None,
        })
        .or_else(|| {
            events.iter().find_map(|event| match event {
                TraceEvent::SchemaHeader { ts_ms, .. } => Some(*ts_ms),
                _ => None,
            })
        })
        .unwrap_or(0)
}

fn last_recorded_model(events: &[TraceEvent]) -> Option<String> {
    events.iter().rev().find_map(|event| match event {
        TraceEvent::LlmCall {
            model: Some(model), ..
        }
        | TraceEvent::LlmResult {
            model: Some(model), ..
        } => Some(model.clone()),
        _ => None,
    })
}

struct EnvGuard {
    saved: Vec<(String, Option<std::ffi::OsString>)>,
}

impl EnvGuard {
    fn set(entries: &[(&str, Option<&std::ffi::OsStr>)]) -> Self {
        let mut saved = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            saved.push(((*key).to_string(), std::env::var_os(key)));
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        Self { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..).rev() {
            match value {
                Some(value) => std::env::set_var(&key, value),
                None => std::env::remove_var(&key),
            }
        }
    }
}
