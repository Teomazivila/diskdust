//! Property-based tests for input parsing and path safety: these functions handle data from
//! external tools, the privileged helper's command line, and the file system.

use std::path::{Path, PathBuf};

use diskdust_core::model::{CleanupAction, KnownCommand};
use diskdust_core::privilege::{decode_payload, encode_payload, validate_admin_action};
use diskdust_core::safety::{SafetyError, SafetyPolicy};
use diskdust_core::units::{parse_docker_size, parse_journal_usage};
use proptest::prelude::*;

fn segment() -> impl Strategy<Value = String> {
    "[A-Za-z0-9 ._'\"-]{1,12}".prop_filter("not . or ..", |s| s != "." && s != "..")
}

fn action() -> impl Strategy<Value = CleanupAction> {
    prop_oneof![
        prop::collection::vec(segment(), 1..5).prop_map(|parts| {
            let path: PathBuf = std::iter::once("/Library/Caches".to_owned()).chain(parts).collect();
            CleanupAction::RemovePath { path, root: PathBuf::from("/Library/Caches") }
        }),
        ("[a-z0-9-]{0,45}", "[0-9]{0,6}")
            .prop_map(|(name, revision)| CleanupAction::Run(KnownCommand::SnapRemoveRevision { name, revision })),
        Just(CleanupAction::Run(KnownCommand::AptClean)),
    ]
}

proptest! {
    #[test]
    fn docker_sizes_round_trip(n in 0u64..1_000_000_000_000_000) {
        prop_assert_eq!(parse_docker_size(&format!("{n}B")), Some(n));
        prop_assert_eq!(parse_docker_size(&format!("{n}B (12%)")), Some(n));
    }

    #[test]
    fn size_parsers_never_panic(s in "\\PC{0,40}") {
        let _ = parse_docker_size(&s);
        let _ = parse_journal_usage(&s);
    }

    #[test]
    fn payload_round_trips(actions in prop::collection::vec(action(), 0..8)) {
        let hex = encode_payload(&actions).expect("encode");
        prop_assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        prop_assert_eq!(decode_payload(&hex).expect("decode"), actions);
    }

    #[test]
    fn payload_decoder_never_panics(s in "\\PC{0,64}") {
        let _ = decode_payload(&s);
    }

    #[test]
    fn helper_only_accepts_fixed_roots_and_well_formed_admin_commands(a in action(), name in segment()) {
        let roots = [PathBuf::from("/Library/Caches")];
        let elsewhere = CleanupAction::RemovePath { path: PathBuf::from("/x").join(&name), root: PathBuf::from("/x") };
        prop_assert!(validate_admin_action(&elsewhere, &roots).is_err());
        if let CleanupAction::Run(cmd) = &a {
            prop_assert_eq!(validate_admin_action(&a, &roots).is_ok(), cmd.is_well_formed());
        } else {
            prop_assert!(validate_admin_action(&a, &roots).is_ok());
        }
    }

    #[test]
    fn traversal_and_relative_paths_are_always_rejected(parts in prop::collection::vec(segment(), 0..4)) {
        let policy = SafetyPolicy::new(Vec::new());
        let mut traversal = PathBuf::from("/tmp");
        traversal.extend(&parts);
        traversal.push("..");
        prop_assert!(matches!(policy.validate(&traversal, Path::new("/tmp")), Err(SafetyError::Traversal(_))));
        if !parts.is_empty() {
            let relative: PathBuf = parts.iter().collect();
            prop_assert!(matches!(policy.validate(&relative, Path::new("/tmp")), Err(SafetyError::NotAbsolute(_))));
        }
    }

    #[test]
    fn ancestors_of_protected_paths_are_protected(parts in prop::collection::vec(segment(), 1..5)) {
        let protected: PathBuf = std::iter::once("/".to_owned()).chain(parts).collect();
        let policy = SafetyPolicy::new([protected.clone()]);
        for ancestor in protected.ancestors() {
            prop_assert!(policy.is_protected(ancestor), "{} must be protected", ancestor.display());
        }
        prop_assert!(!policy.is_protected(&protected.join("child")));
    }

    #[test]
    fn validated_paths_are_strictly_inside_root(parts in prop::collection::vec(segment(), 1..4)) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical").join("root");
        let target: PathBuf = std::iter::once(root.clone()).chain(parts.iter().map(PathBuf::from)).collect();
        std::fs::create_dir_all(&target).expect("mkdir");
        let policy = SafetyPolicy::new(Vec::new());
        let ok = policy.validate(&target, &root).expect("inside root");
        prop_assert!(ok.starts_with(&root) && ok != root);
        prop_assert!(policy.validate(&root, &root).is_err());
    }
}
