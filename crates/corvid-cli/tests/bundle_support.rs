use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

const TEST_SEED_HEX: &str =
    "4242424242424242424242424242424242424242424242424242424242424242";

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

pub fn corvid_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_corvid"))
}

pub fn shared_library_name(stem: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("lib{stem}.dylib")
    } else if cfg!(windows) {
        format!("{stem}.dll")
    } else {
        format!("lib{stem}.so")
    }
}

fn tools_staticlib_name() -> &'static str {
    if cfg!(windows) {
        "corvid_test_tools.lib"
    } else {
        "libcorvid_test_tools.a"
    }
}

fn target_triple() -> &'static str {
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "x86_64-apple-darwin"
    } else if cfg!(windows) && cfg!(target_arch = "x86_64") {
        "x86_64-pc-windows-msvc"
    } else {
        "unknown-target"
    }
}

fn python_command() -> Option<Vec<String>> {
    let candidates = if cfg!(windows) {
        vec![
            vec!["py".to_string(), "-3".to_string()],
            vec!["python".to_string()],
        ]
    } else {
        vec![vec!["python3".to_string()], vec!["python".to_string()]]
    };
    for candidate in candidates {
        let mut probe = Command::new(&candidate[0]);
        for arg in &candidate[1..] {
            probe.arg(arg);
        }
        if probe
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
        {
            return Some(candidate);
        }
    }
    None
}

pub fn run_corvid(args: &[&str], cwd: &Path) -> Output {
    Command::new(corvid_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("run corvid")
}

fn test_tools_lib_path() -> PathBuf {
    let root = workspace_root();
    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("corvid-test-tools")
        .arg("--release")
        .current_dir(&root)
        .status()
        .expect("build corvid-test-tools");
    assert!(status.success(), "building corvid-test-tools failed");
    root.join("target").join("release").join(tools_staticlib_name())
}

pub struct BundleFixture {
    _temp: tempfile::TempDir,
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub descriptor_path: PathBuf,
    pub library_path: PathBuf,
}

pub fn create_fixture() -> BundleFixture {
    let _guard = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().to_path_buf();
    let src_dir = root.join("src");
    let traces_dir = root.join("traces");
    let keys_dir = root.join("keys");
    let artifacts_dir = root.join("artifacts");
    fs::create_dir_all(&src_dir).expect("create src");
    fs::create_dir_all(&traces_dir).expect("create traces");
    fs::create_dir_all(&keys_dir).expect("create keys");
    fs::create_dir_all(&artifacts_dir).expect("create artifacts");

    let demo_source = workspace_root()
        .join("examples")
        .join("cdylib_catalog_demo")
        .join("src")
        .join("classify.cor");
    let source_path = src_dir.join("classify.cor");
    fs::copy(&demo_source, &source_path).expect("copy demo source");

    let bundled_tools = artifacts_dir.join(tools_staticlib_name());
    fs::copy(test_tools_lib_path(), &bundled_tools).expect("copy tools staticlib");

    let build = run_corvid(
        &[
            "build",
            source_path.to_str().expect("utf8 source"),
            "--target=cdylib",
            "--with-tools-lib",
            bundled_tools.to_str().expect("utf8 tools"),
            "--all-artifacts",
        ],
        &root,
    );
    assert!(
        build.status.success(),
        "build fixture failed: stdout={} stderr={}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let release_dir = root.join("target").join("release");
    let library_path = release_dir.join(shared_library_name("classify"));
    let descriptor_path = release_dir.join("classify.corvid-abi.json");
    let header_path = release_dir.join("lib_classify.h");
    assert!(library_path.exists(), "missing library {}", library_path.display());
    assert!(
        descriptor_path.exists(),
        "missing descriptor {}",
        descriptor_path.display()
    );
    assert!(header_path.exists(), "missing header {}", header_path.display());

    let rust_bindings = root.join("bindings_rust");
    let python_bindings = root.join("bindings_python");
    let rust_bind = run_corvid(
        &[
            "bind",
            "rust",
            descriptor_path.to_str().expect("utf8 descriptor"),
            "--out",
            rust_bindings.to_str().expect("utf8 rust out"),
        ],
        &root,
    );
    assert!(rust_bind.status.success(), "rust bind failed: {}", String::from_utf8_lossy(&rust_bind.stderr));
    let python_bind = run_corvid(
        &[
            "bind",
            "python",
            descriptor_path.to_str().expect("utf8 descriptor"),
            "--out",
            python_bindings.to_str().expect("utf8 python out"),
        ],
        &root,
    );
    assert!(
        python_bind.status.success(),
        "python bind failed: {}",
        String::from_utf8_lossy(&python_bind.stderr)
    );

    let trace_safe = traces_dir.join("safe.jsonl");
    let safe_result = record_classify_trace(
        &root,
        &library_path,
        &trace_safe,
        "I loved the support experience",
        "positive",
    );
    let trace_approval = traces_dir.join("approval.jsonl");
    let approval_result = record_issue_tag_trace(&python_bindings, &library_path, &trace_approval, "approved");
    let trace_grounded = traces_dir.join("grounded.jsonl");
    let (grounded_result, grounded_sources) = record_grounded_tag_trace(
        &root,
        &library_path,
        &trace_grounded,
        "catalog-proof",
    );
    let trace_observation = traces_dir.join("observation.jsonl");
    let observation_result = record_classify_trace(
        &root,
        &library_path,
        &trace_observation,
        "The package arrived yesterday with careful follow-up notes",
        "neutral",
    );

    let verify_key_path = keys_dir.join("verify.hex");
    let envelope_path = keys_dir.join("receipt.envelope.json");
    write_signed_receipt(&verify_key_path, &envelope_path);

    let manifest = BundleManifestForTests {
        bundle_schema_version: 1,
        name: "phase22-temp-bundle".to_string(),
        target_triple: target_triple().to_string(),
        primary_source: rel(&root, &source_path),
        tools_staticlib_path: Some(rel(&root, &bundled_tools)),
        library_path: rel(&root, &library_path),
        descriptor_path: rel(&root, &descriptor_path),
        header_path: Some(rel(&root, &header_path)),
        bindings_rust_dir: rel(&root, &rust_bindings),
        bindings_python_dir: rel(&root, &python_bindings),
        capsule_path: None,
        receipt_envelope_path: Some(rel(&root, &envelope_path)),
        receipt_verify_key_path: Some(rel(&root, &verify_key_path)),
        traces: vec![
            TraceForTests {
                name: "safe".to_string(),
                path: rel(&root, &trace_safe),
                source: rel(&root, &source_path),
                sha256: sha256_file(&trace_safe),
                expected_agent: "classify".to_string(),
                expected_result_json: serde_json::to_string(&safe_result).unwrap(),
                expected_grounded_sources: Vec::new(),
                expected_observation: Some(true),
            },
            TraceForTests {
                name: "approval".to_string(),
                path: rel(&root, &trace_approval),
                source: rel(&root, &source_path),
                sha256: sha256_file(&trace_approval),
                expected_agent: "issue_tag".to_string(),
                expected_result_json: serde_json::to_string(&approval_result).unwrap(),
                expected_grounded_sources: Vec::new(),
                expected_observation: Some(true),
            },
            TraceForTests {
                name: "grounded".to_string(),
                path: rel(&root, &trace_grounded),
                source: rel(&root, &source_path),
                sha256: sha256_file(&trace_grounded),
                expected_agent: "grounded_tag".to_string(),
                expected_result_json: serde_json::to_string(&grounded_result).unwrap(),
                expected_grounded_sources: grounded_sources,
                expected_observation: Some(true),
            },
            TraceForTests {
                name: "observation".to_string(),
                path: rel(&root, &trace_observation),
                source: rel(&root, &source_path),
                sha256: sha256_file(&trace_observation),
                expected_agent: "classify".to_string(),
                expected_result_json: serde_json::to_string(&observation_result).unwrap(),
                expected_grounded_sources: Vec::new(),
                expected_observation: Some(true),
            },
        ],
        hashes: HashesForTests {
            library: sha256_file(&library_path),
            descriptor: sha256_file(&descriptor_path),
            header: Some(sha256_file(&header_path)),
            bindings_rust: sha256_dir(&rust_bindings),
            bindings_python: sha256_dir(&python_bindings),
            capsule: None,
            receipt_envelope: Some(sha256_file(&envelope_path)),
            receipt_verify_key: Some(sha256_file(&verify_key_path)),
            tools_staticlib: Some(sha256_file(&bundled_tools)),
        },
    };
    let manifest_path = root.join("corvid-bundle.toml");
    fs::write(&manifest_path, toml::to_string_pretty(&manifest).unwrap()).expect("write manifest");

    BundleFixture {
        _temp: temp,
        root,
        manifest_path,
        descriptor_path,
        library_path,
    }
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("bundle child")
        .to_string_lossy()
        .replace('\\', "/")
}

fn record_classify_trace(
    package_dir: &Path,
    library: &Path,
    trace: &Path,
    text: &str,
    reply: &str,
) -> String {
    let python = python_command().expect("python is required for bundle fixture tests");
    let script_path = package_dir.join("record_classify.py");
    fs::write(
        &script_path,
        format!(
            r#"import ctypes
import json
import os
import sys


class ApprovalRequired(ctypes.Structure):
    _fields_ = [
        ("site_name", ctypes.c_char_p),
        ("predicate_json", ctypes.c_char_p),
        ("args_json", ctypes.c_char_p),
        ("rationale_prompt", ctypes.c_char_p),
    ]


def main() -> int:
    library = ctypes.CDLL(sys.argv[1])
    library.corvid_call_agent.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ApprovalRequired),
    ]
    library.corvid_call_agent.restype = ctypes.c_uint32
    library.corvid_free_result.argtypes = [ctypes.c_void_p]
    library.corvid_free_result.restype = None
    library.corvid_observation_release.argtypes = [ctypes.c_uint64]
    library.corvid_observation_release.restype = None

    args_json = json.dumps([{text:?}]).encode("utf-8")
    result = ctypes.c_char_p()
    result_len = ctypes.c_size_t()
    observation = ctypes.c_uint64()
    approval = ApprovalRequired()
    status = library.corvid_call_agent(
        b"classify",
        args_json,
        len(args_json),
        ctypes.byref(result),
        ctypes.byref(result_len),
        ctypes.byref(observation),
        ctypes.byref(approval),
    )
    if status != 0:
        raise SystemExit(status)
    payload = ctypes.string_at(result, result_len.value).decode("utf-8")
    if observation.value:
        library.corvid_observation_release(observation.value)
    if result.value:
        library.corvid_free_result(result)
    print(json.loads(payload), flush=True)
    os._exit(0)


if __name__ == "__main__":
    raise SystemExit(main())
"#
        ),
    )
    .expect("write python classify trace script");

    let mut command = Command::new(&python[0]);
    for arg in &python[1..] {
        command.arg(arg);
    }
    let output = command
        .arg(&script_path)
        .arg(library)
        .current_dir(package_dir)
        .env("CORVID_TRACE_PATH", trace)
        .env_remove("CORVID_TRACE_DISABLE")
        .env_remove("CORVID_REPLAY_TRACE_PATH")
        .env_remove("CORVID_DETERMINISTIC_SEED")
        .env("CORVID_MODEL", "mock-1")
        .env("CORVID_TEST_MOCK_LLM", "1")
        .env(
            "CORVID_TEST_MOCK_LLM_REPLIES",
            format!(r#"{{"classify_prompt":"{reply}"}}"#),
        )
        .output()
        .expect("run python classify trace recorder");
    assert!(
        output.status.success(),
        "python classify trace recorder failed: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8 python stdout")
        .trim()
        .to_owned()
}

fn record_issue_tag_trace(package_dir: &Path, library: &Path, trace: &Path, value: &str) -> String {
    let python = python_command().expect("python is required for bundle fixture tests");
    let script_path = package_dir.join("record_issue_tag.py");
    fs::write(
        &script_path,
        format!(
            r#"from classify import ApprovalDecision, ApprovalRequest, Client
import os


class AcceptApprover:
    def decide(self, _request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision.ACCEPT


def main() -> int:
    import sys

    client = Client(sys.argv[1])
    issued, _ = client.issue_tag({value:?}, approver=AcceptApprover())
    print(issued, flush=True)
    os._exit(0)


if __name__ == "__main__":
    raise SystemExit(main())
"#
        ),
    )
    .expect("write python trace script");

    let mut command = Command::new(&python[0]);
    for arg in &python[1..] {
        command.arg(arg);
    }
    let output = command
        .arg(&script_path)
        .arg(library)
        .current_dir(package_dir)
        .env("CORVID_TRACE_PATH", trace)
        .env_remove("CORVID_TRACE_DISABLE")
        .env_remove("CORVID_REPLAY_TRACE_PATH")
        .env_remove("CORVID_DETERMINISTIC_SEED")
        .env("CORVID_MODEL", "mock-1")
        .env("CORVID_TEST_MOCK_LLM", "1")
        .env(
            "CORVID_TEST_MOCK_LLM_REPLIES",
            r#"{"classify_prompt":"positive"}"#,
        )
        .output()
        .expect("run python trace recorder");
    assert!(
        output.status.success(),
        "python trace recorder failed: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8 python stdout")
        .trim()
        .to_owned()
}

fn record_grounded_tag_trace(
    package_dir: &Path,
    library: &Path,
    trace: &Path,
    value: &str,
) -> (String, Vec<String>) {
    let python = python_command().expect("python is required for bundle fixture tests");
    let script_path = package_dir.join("record_grounded_tag.py");
    fs::write(
        &script_path,
        format!(
            r#"import ctypes
import json
import os
import sys


def main() -> int:
    library = ctypes.CDLL(sys.argv[1])
    library.grounded_tag.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
    ]
    library.grounded_tag.restype = ctypes.c_void_p
    library.corvid_grounded_sources.argtypes = [
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.c_size_t,
    ]
    library.corvid_grounded_sources.restype = ctypes.c_int32
    library.corvid_grounded_release.argtypes = [ctypes.c_uint64]
    library.corvid_grounded_release.restype = None
    library.corvid_observation_release.argtypes = [ctypes.c_uint64]
    library.corvid_observation_release.restype = None
    library.corvid_free_string.argtypes = [ctypes.c_void_p]
    library.corvid_free_string.restype = None

    grounded_handle = ctypes.c_uint64()
    observation = ctypes.c_uint64()
    value_ptr = library.grounded_tag(
        {value:?}.encode("utf-8"),
        ctypes.byref(grounded_handle),
        ctypes.byref(observation),
    )
    if not value_ptr:
        raise SystemExit(1)
    payload = ctypes.string_at(value_ptr).decode("utf-8")
    source_count = library.corvid_grounded_sources(grounded_handle.value, None, 0)
    if source_count < 0:
        raise SystemExit(2)
    sources = []
    if source_count:
        source_array = (ctypes.c_char_p * source_count)()
        library.corvid_grounded_sources(
            grounded_handle.value,
            source_array,
            source_count,
        )
        sources = [source_array[idx].decode("utf-8") for idx in range(source_count)]
    if observation.value:
        library.corvid_observation_release(observation.value)
    if grounded_handle.value:
        library.corvid_grounded_release(grounded_handle.value)
    library.corvid_free_string(value_ptr)
    print(json.dumps({{"value": payload, "sources": sources}}), flush=True)
    os._exit(0)


if __name__ == "__main__":
    raise SystemExit(main())
"#
        ),
    )
    .expect("write python grounded trace script");

    let mut command = Command::new(&python[0]);
    for arg in &python[1..] {
        command.arg(arg);
    }
    let output = command
        .arg(&script_path)
        .arg(library)
        .current_dir(package_dir)
        .env("CORVID_TRACE_PATH", trace)
        .env_remove("CORVID_TRACE_DISABLE")
        .env_remove("CORVID_REPLAY_TRACE_PATH")
        .env_remove("CORVID_DETERMINISTIC_SEED")
        .output()
        .expect("run python grounded trace recorder");
    assert!(
        output.status.success(),
        "python grounded trace recorder failed: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse grounded trace stdout");
    let value = payload
        .get("value")
        .and_then(|value| value.as_str())
        .expect("grounded payload value")
        .to_owned();
    let sources = payload
        .get("sources")
        .and_then(|value| value.as_array())
        .expect("grounded payload sources")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("grounded source string")
                .to_owned()
        })
        .collect();
    (value, sources)
}

fn write_signed_receipt(verify_key_path: &Path, envelope_path: &Path) {
    let mut seed = [0u8; 32];
    hex::decode_to_slice(TEST_SEED_HEX, &mut seed).expect("seed");
    let signing = SigningKey::from_bytes(&seed);
    fs::write(verify_key_path, hex::encode(signing.verifying_key().to_bytes())).expect("write verify key");

    let payload = serde_json::json!({
        "schema_version": 2,
        "kind": "bundle-test",
        "signed": true
    });
    let payload_bytes = serde_json::to_vec(&payload).expect("payload json");
    let pae = pae("application/vnd.corvid-receipt+json", &payload_bytes);
    let signature = signing.sign(&pae);
    let envelope = serde_json::json!({
        "payloadType": "application/vnd.corvid-receipt+json",
        "payload": base64::engine::general_purpose::STANDARD.encode(&payload_bytes),
        "signatures": [{
            "keyid": "corvid-test",
            "sig": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        }]
    });
    fs::write(envelope_path, serde_json::to_vec_pretty(&envelope).unwrap()).expect("write envelope");
}

fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
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

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|err| {
        panic!("read file for hashing `{}`: {err}", path.display())
    });
    sha256_bytes(&bytes)
}

pub fn sha256_file_for_tests(path: &Path) -> String {
    sha256_file(path)
}

fn sha256_dir(path: &Path) -> String {
    let mut files = Vec::new();
    collect_files(path, path, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    for (relative, bytes) in files {
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(bytes.len().to_le_bytes());
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

fn collect_files(root: &Path, current: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let mut entries = fs::read_dir(current)
        .expect("read dir")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("dir entries");
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out);
        } else {
            out.push((
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                fs::read(&path).expect("read file"),
            ));
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Serialize)]
struct BundleManifestForTests {
    bundle_schema_version: u32,
    name: String,
    target_triple: String,
    primary_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools_staticlib_path: Option<String>,
    library_path: String,
    descriptor_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    header_path: Option<String>,
    bindings_rust_dir: String,
    bindings_python_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    capsule_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_envelope_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_verify_key_path: Option<String>,
    traces: Vec<TraceForTests>,
    hashes: HashesForTests,
}

#[derive(Serialize)]
struct TraceForTests {
    name: String,
    path: String,
    source: String,
    sha256: String,
    expected_agent: String,
    expected_result_json: String,
    expected_grounded_sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_observation: Option<bool>,
}

#[derive(Serialize)]
struct HashesForTests {
    library: String,
    descriptor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<String>,
    bindings_rust: String,
    bindings_python: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    capsule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_envelope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_verify_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools_staticlib: Option<String>,
}

