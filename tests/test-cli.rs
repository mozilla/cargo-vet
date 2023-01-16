// These tests largely just check that basic CLI configs still work,
// and show you how you've changed the output. Yes, a lot of these
// will randomly churn (especially the help message ones, which
// contain the latest version), but this is good for two reasons:
//
// * You can easily see exactly what you changed
// * It can prompt you to update any other docs
//
// `cargo insta` automates reviewing and updating these snapshots.
// You can install `cargo insta` with:
//
// > cargo install cargo-insta
//
// Also note that `cargo test` for an application adds our binary to
// the env as `CARGO_BIN_EXE_<name>`.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

// Some tests need to write files (and read them back).
// To keep this tidy and hidden, we make a new directory
// in `target`.
// const TEST_TMP: &str = "../target/testdata/";

// NOTE: We filter out the "Blocking: waiting for file lock" lines, as they are
// printed out non-deterministically when there is file contention.
fn filter_blocking_lines(stderr: &[u8]) -> String {
    std::str::from_utf8(stderr)
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("Blocking: waiting for file lock"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_outputs(output: &Output) -> String {
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = filter_blocking_lines(&output.stderr);
    format!("stdout:\n{stdout}\nstderr:\n{stderr}")
}

fn format_diff_outputs(output: &Output) -> String {
    // Filter out lines which may contain paths so that the output is portable,
    // while preserving some of the general format.
    let stdout = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("diff --git"))
        .map(|line| {
            if let Some(path) = line.strip_prefix("--- ") {
                return format!(
                    "--- a/{}",
                    Path::new(path).file_name().unwrap().to_str().unwrap()
                );
            }
            if let Some(path) = line.strip_prefix("+++ ") {
                return format!(
                    "+++ b/{}",
                    Path::new(path).file_name().unwrap().to_str().unwrap()
                );
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let stderr = filter_blocking_lines(&output.stderr);
    format!("stdout:\n{stdout}\nstderr:\n{stderr}")
}

#[test]
fn test_version() {
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .arg("vet")
        .arg("-V")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success(), "{}", stderr);
    assert_eq!(stderr, "");

    let (name, ver) = stdout.split_once(' ').unwrap();
    assert_eq!(name, "cargo-vet");
    let mut ver_parts = ver.trim().split('.');
    ver_parts.next().unwrap().parse::<u8>().unwrap();
    ver_parts.next().unwrap().parse::<u8>().unwrap();
    ver_parts.next().unwrap().parse::<u8>().unwrap();
    assert!(ver_parts.next().is_none());
}

#[test]
fn test_long_help() {
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .arg("vet")
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("long-help", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_short_help() {
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .arg("vet")
        .arg("-h")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("short-help", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_markdown_help() {
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .arg("vet")
        .arg("help-markdown")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("markdown-help", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("--diff-cache")
        .arg("../diff-cache.toml")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_json() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("--diff-cache")
        .arg("../diff-cache.toml")
        .arg("--output-format=json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-json", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_suggest() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("suggest")
        .arg("--diff-cache")
        .arg("../diff-cache.toml")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-suggest", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_suggest_json() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("suggest")
        .arg("--diff-cache")
        .arg("../diff-cache.toml")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("--output-format=json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-suggest-json", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_suggest_shallow() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("suggest")
        .arg("--diff-cache")
        .arg("../diff-cache.toml")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("--shallow")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-suggest-shallow", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_suggest_shallow_json() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("suggest")
        .arg("--diff-cache")
        .arg("../diff-cache.toml")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("--output-format=json")
        .arg("--shallow")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-suggest-shallow-json", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_dump_graph_full_json() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("dump-graph")
        .arg("--diff-cache")
        .arg("../diff-cache.toml")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("--output-format=json")
        .arg("--depth=full")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-dump-graph-full-json", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_dump_graph_full() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("dump-graph")
        .arg("--diff-cache")
        .arg("../diff-cache.toml")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("--depth=full")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-dump-graph-full", format_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_bad_certify_human() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("certify")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("asdfsdfs")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-bad-certify-human", format_outputs(&output));
    assert!(!output.status.success(), "{}", output.status);
}

#[test]
fn test_project_bad_certify_json() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let output = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("certify")
        .arg("--output-format=json")
        .arg("--manifest-path")
        .arg("Cargo.toml")
        .arg("asdfsdfs")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    insta::assert_snapshot!("test-project-bad-certify-json", format_outputs(&output));
    assert!(!output.status.success(), "{}", output.status);
}

#[test]
fn test_project_diff_output() {
    // Test that the diff output from `cargo vet diff` is correctly filtered to
    // remove files like .cargo_vcs_info.json.

    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let mut child = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("diff")
        .arg("--mode")
        .arg("local")
        .arg("syn")
        .arg("1.0.90")
        .arg("1.0.91")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"\n").unwrap();

    let output = child.wait_with_output().unwrap();

    insta::assert_snapshot!("test-project-diff-output", format_diff_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}

#[test]
fn test_project_diff_output_git() {
    // Test that the diff output handles git revisions.

    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test-project");
    let bin = env!("CARGO_BIN_EXE_cargo-vet");
    let mut child = Command::new(bin)
        .current_dir(&project)
        .arg("vet")
        .arg("diff")
        .arg("--mode")
        .arg("local")
        .arg("proc-macro2")
        .arg("1.0.37")
        .arg("1.0.37@git:4445659b0f753a928059244c875a58bb12f791e9")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"\n").unwrap();

    let output = child.wait_with_output().unwrap();

    insta::assert_snapshot!("test-project-diff-output-git", format_diff_outputs(&output));
    assert!(output.status.success(), "{}", output.status);
}
