# Corvid Bundle Format

`corvid-bundle.toml` is the manifest for a checked-in Corvid bundle.

The format is intended for reviewable, reproducible AI deployment artifacts:

- source
- built cdylib
- ABI descriptor
- generated host bindings
- recorded traces
- signed receipts

Schema version: `1`

Versioning rules:

- additive fields do not bump the schema version
- semantic meaning changes do bump the schema version
- unknown extra fields are allowed and preserved by consumers

## Scope

Version 1 treats Linux as the canonical strict-rebuild target.

`corvid bundle verify <path> --rebuild` is therefore defined as:

- supported on Linux
- strict byte-for-byte for rebuilt artifacts
- unsupported on non-Linux hosts, which fail with `BundlePlatformUnsupported`

Plain `corvid bundle verify <path>` remains cross-platform because it only checks committed artifacts and signatures.

## Directory Layout

A bundle is a directory containing `corvid-bundle.toml` plus the files it references.

Typical layout:

```text
phase22_demo/
  corvid-bundle.toml
  src/
  artifacts/
  bindings_rust/
  bindings_python/
  traces/
  receipts/
  keys/
```

All manifest paths are relative to the directory containing `corvid-bundle.toml`.

## Manifest Schema

Example:

```toml
bundle_schema_version = 1
name = "phase22-demo"
target_triple = "x86_64-unknown-linux-gnu"
primary_source = "src/classify.cor"
tools_staticlib_path = "artifacts/libcorvid_test_tools.a"
library_path = "artifacts/libclassify.so"
descriptor_path = "artifacts/classify.corvid-abi.json"
header_path = "artifacts/lib_classify.h"
bindings_rust_dir = "bindings_rust"
bindings_python_dir = "bindings_python"
capsule_path = "artifacts/replay_capsule.tar"
receipt_envelope_path = "receipts/receipt.envelope.json"
receipt_verify_key_path = "keys/verify.hex"

[[traces]]
name = "safe"
path = "traces/safe.jsonl"
source = "src/classify.cor"
sha256 = "..."
expected_agent = "classify"
expected_result_json = "\"positive\""
expected_observation = true

[hashes]
library = "..."
descriptor = "..."
header = "..."
bindings_rust = "..."
bindings_python = "..."
capsule = "..."
receipt_envelope = "..."
receipt_verify_key = "..."
tools_staticlib = "..."
```

### Top-level fields

- `bundle_schema_version`
  - required integer
  - must equal `1` for v1 consumers

- `name`
  - required string
  - human-readable bundle identifier

- `target_triple`
  - required string
  - target the bundle artifacts were built for

- `primary_source`
  - required string
  - entry `.cor` file used for rebuild

- `tools_staticlib_path`
  - optional string
  - static library passed through `--with-tools-lib` during rebuild

- `library_path`
  - required string
  - built cdylib artifact

- `descriptor_path`
  - required string
  - emitted `*.corvid-abi.json`

- `header_path`
  - optional string
  - emitted C header, when present

- `bindings_rust_dir`
  - required string
  - generated Rust package root

- `bindings_python_dir`
  - required string
  - generated Python package root

- `capsule_path`
  - optional string
  - replay capsule artifact

- `receipt_envelope_path`
  - optional string
  - DSSE envelope path for signed receipt verification

- `receipt_verify_key_path`
  - optional string
  - verifying key for the DSSE envelope

- `traces`
  - required array, may be empty
  - replay fixtures included in the bundle

- `hashes`
  - required table
  - committed expected hashes for primary artifacts

### Trace entries

Each trace entry has:

- `name`
  - logical trace label

- `path`
  - relative trace path

- `source`
  - source file the trace corresponds to

- `sha256`
  - expected hash of the trace file

- `expected_agent`
  - exported agent name expected during replay

- `expected_result_json`
  - canonical JSON string expected from replay

- `expected_grounded_sources`
  - reserved list for grounded-source verification

- `expected_observation`
  - optional boolean indicating whether replay should yield an observation handle

### Hash table

Artifact hashes are SHA-256 hex strings.

Supported keys:

- `library`
- `descriptor`
- `header`
- `bindings_rust`
- `bindings_python`
- `capsule`
- `receipt_envelope`
- `receipt_verify_key`
- `tools_staticlib`

Directory hashes are computed over:

- relative path bytes
- a `0x00` separator
- file length as little-endian bytes
- file contents

This makes directory hashing stable across file ordering differences.

## Verification Semantics

`corvid bundle verify <path>` performs committed-artifact verification:

- parses `corvid-bundle.toml`
- checks schema version
- recomputes all declared hashes
- validates trace schema
- checks that each trace records the expected agent
- verifies the DSSE envelope when receipt fields are present

`corvid bundle verify <path> --rebuild` additionally:

- rebuilds the descriptor from `primary_source`
- rebuilds the cdylib from `primary_source`
- compares rebuilt descriptor bytes against the committed descriptor
- compares rebuilt library bytes against the committed library
- regenerates Rust and Python bindings from the rebuilt descriptor
- compares generated bindings against the committed bindings
- replays each trace against the rebuilt library

Rebuild comparison is strict:

- no semantic-equivalence fallback
- no timestamp tolerance at verify time
- nondeterminism must be removed at emission time, not ignored later

## Drift and Failure Classes

Current typed failure classes include:

- `BundleSchemaVersionMismatch`
- `BundleHashMismatch`
- `BundleRebuildMismatch`
- `BundlePlatformUnsupported`
- `BundleTraceAgentMismatch`
- `BundleReplayMismatch`
- `BundleSignatureVerifyFailed`

These are intended to be review-facing failures, not opaque internal errors.

## Extra Fields

Consumers must ignore unknown top-level fields.

That allows bundle producers to attach additive metadata without breaking older verifiers.

## Design Intent

The bundle format is not meant to be a private Corvid cache.

It is meant to be:

- diffable in code review
- auditable offline
- rebuildable by third parties
- signed without changing artifact bytes
- strict enough that a mismatch is evidence, not an implementation detail
