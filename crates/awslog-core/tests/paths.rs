//! FR-7 portable case root resolution (docs/07-case-layout.md).

use std::path::{Path, PathBuf};

use awslog_core::paths::{self, PathError, RootSources};
use time::macros::datetime;

fn sources<'a>(env: Option<&'a Path>, cli: Option<&'a Path>, exe: &'a Path) -> RootSources<'a> {
    RootSources {
        env_dir: env,
        cli_dir: cli,
        exe_dir: exe,
    }
}

#[test]
fn env_var_wins_over_cli_and_exe_dir() {
    let env = PathBuf::from("/from/env");
    let cli = PathBuf::from("/from/cli");
    let exe = PathBuf::from("/from/exe");

    let root = paths::resolve(&sources(Some(&env), Some(&cli), &exe));

    assert_eq!(root, env);
}

#[test]
fn cli_wins_over_exe_dir() {
    let cli = PathBuf::from("/from/cli");
    let exe = PathBuf::from("/from/exe");

    let root = paths::resolve(&sources(None, Some(&cli), &exe));

    assert_eq!(root, cli);
}

#[test]
fn falls_back_to_cases_beside_executable() {
    let exe = PathBuf::from("/opt/tool");

    let root = paths::resolve(&sources(None, None, &exe));

    assert_eq!(root, PathBuf::from("/opt/tool/cases"));
}

#[test]
fn macos_app_bundle_resolves_next_to_bundle() {
    // Executable lives in Foo.app/Contents/MacOS; cases/ belongs beside Foo.app.
    let exe_dir = Path::new("/Applications/Foo.app/Contents/MacOS");

    let base = paths::portable_base_dir(exe_dir);

    assert_eq!(base, Path::new("/Applications"));
}

#[test]
fn non_bundle_exe_dir_is_its_own_base() {
    let exe_dir = Path::new("/opt/tool");

    assert_eq!(paths::portable_base_dir(exe_dir), exe_dir);
}

#[test]
fn prepare_creates_missing_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("cases");

    let prepared = paths::prepare(&root).expect("writable root");

    assert!(prepared.path().is_dir());
    assert_eq!(prepared.path(), root);
}

// Windows' read-only bit does not stop child creation; denying write there
// needs an ACL, which the Windows CI does with icacls against the real exe
// (build-windows.yml "Verify unwritable root fails").
#[cfg(unix)]
#[test]
fn prepare_fails_on_read_only_parent_without_falling_back() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().join("locked");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();

    let err = paths::prepare(&parent.join("cases")).expect_err("must not fall back");

    // The error names the attempted path so the user can act on it (no AppData fallback).
    match err {
        PathError::NotWritable { ref path, .. } => assert!(path.ends_with("cases")),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn create_case_builds_timestamped_directory_with_subdirs() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();

    let case = root
        .create_case(
            Path::new("/logs/AWSLogs/prod"),
            datetime!(2026-09-11 14:03:07),
        )
        .unwrap();

    assert_eq!(case.id(), "20260911-140307-prod");
    assert!(case.dir().join("rules").is_dir());
    assert!(case.dir().join("exports").is_dir());
    assert!(case.dir().join("logs").is_dir());
    assert_eq!(case.session_db(), case.dir().join("session.duckdb"));
}

#[test]
fn case_id_slug_sanitizes_input_directory_name() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();

    let case = root
        .create_case(
            Path::new("/logs/My Logs (2026)!"),
            datetime!(2026-01-02 03:04:05),
        )
        .unwrap();

    assert_eq!(case.id(), "20260102-030405-my-logs-2026");
}

#[test]
fn create_case_twice_in_same_second_does_not_collide() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();
    let at = datetime!(2026-09-11 14:03:07);

    let first = root.create_case(Path::new("/logs/prod"), at).unwrap();
    let second = root.create_case(Path::new("/logs/prod"), at).unwrap();

    assert_ne!(first.id(), second.id());
    assert!(second.dir().is_dir());
}

#[test]
fn case_ids_that_could_escape_the_root_are_rejected() {
    for bad in ["../escape", "a/b", "a\\b", "", "."] {
        assert!(!paths::is_safe_case_id(bad), "accepted {bad:?}");
    }
    assert!(paths::is_safe_case_id("20260911-140307-prod"));
}

#[test]
fn case_dir_refuses_unsafe_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();

    assert!(root.case_dir("../../etc").is_none());
    assert!(root.case_dir("20260911-140307-prod").is_some());
}

#[test]
fn list_cases_returns_newest_first_and_ignores_stray_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();
    for id in ["20260101-000000-a", "20260909-000000-b"] {
        let dir = root.path().join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("case.json"), b"{}").unwrap();
    }
    // A directory without case.json is not a case.
    std::fs::create_dir_all(root.path().join("scratch")).unwrap();

    let ids = root.list_cases().unwrap();

    assert_eq!(ids, ["20260909-000000-b", "20260101-000000-a"]);
}

#[test]
fn delete_case_removes_the_whole_case_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();
    let case = root
        .create_case(Path::new("/logs/prod"), datetime!(2026-09-11 14:03:07))
        .unwrap();
    let id = case.id().to_owned();
    std::fs::write(case.dir().join("case.json"), "{}").unwrap();
    std::fs::write(case.session_db(), b"db").unwrap();

    root.delete_case(&id).unwrap();

    assert!(!case.dir().exists());
    assert!(root.list_cases().unwrap().is_empty());
}

#[test]
fn delete_case_refuses_ids_that_could_escape_the_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();
    let outsider = tmp.path().join("keep.txt");
    std::fs::write(&outsider, b"evidence").unwrap();

    assert!(root.delete_case("../keep.txt").is_err());
    assert!(root.delete_case("..").is_err());

    // A traversal attempt must not touch anything outside the root.
    assert!(outsider.exists());
}

#[test]
fn deleting_a_missing_case_is_an_error_not_a_silent_success() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();

    assert!(root.delete_case("20260101-000000-nope").is_err());
}

#[test]
fn delete_case_refuses_directories_that_are_not_cases() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();
    let stray = root.path().join("20260101-000000-notacase");
    std::fs::create_dir_all(stray.join("photos")).unwrap();
    std::fs::write(stray.join("photos/holiday.jpg"), b"jpeg").unwrap();

    assert!(root.delete_case("20260101-000000-notacase").is_err());
    assert!(
        stray.exists(),
        "a recursive delete must not run on foreign data"
    );
}

#[test]
fn delete_case_still_removes_a_half_deleted_case() {
    let tmp = tempfile::tempdir().unwrap();
    let root = paths::prepare(&tmp.path().join("cases")).unwrap();
    let case = root
        .create_case(Path::new("/logs/prod"), datetime!(2026-09-11 14:03:07))
        .unwrap();
    std::fs::write(case.session_db(), b"db").unwrap();

    // An interrupted delete leaves the db but no case.json; list_cases hides
    // it, so requiring case.json here would strand it forever.
    root.delete_case(case.id()).unwrap();

    assert!(!case.dir().exists());
}
