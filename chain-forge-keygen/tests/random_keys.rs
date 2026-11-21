//! qcb-keygen must produce a fresh random ML-DSA-65 key on every run.

use std::process::Command;

fn run(scheme: &str, label: &str) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_qcb-keygen")).args([scheme, label]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn same_label_never_yields_the_same_key() {
    let a = run("mldsa", "alice");
    let b = run("mldsa", "alice");
    assert_ne!(a["private_key"], b["private_key"], "mldsa: the key must not be derivable from the label");
    assert_ne!(a["public_key"], b["public_key"], "mldsa");
}
