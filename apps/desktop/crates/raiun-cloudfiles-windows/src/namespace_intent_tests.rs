use super::*;

fn parent() -> NamespaceParent {
    NamespaceParent {
        scope: EditJournalScope {
            profile_id: "default".into(),
            server_origin: "https://cloud.example.test".into(),
            account_subject: "account-a".into(),
            space_id: "personal-a".into(),
            root_resource_id: "remote-root-a".into(),
            root_volume_serial: 7,
            root_file_index: 11,
        },
        authorization: CapturedAuthorization {
            agent_generation: 3,
            token_generation: 2,
        },
        classification: StorageClassification::Ordinary,
        local_file: LocalFileIdentity {
            volume_serial: 7,
            file_index: 12,
        },
        local_components: vec!["Personal".into()],
        remote: RemoteEditBaseline {
            resource_id: "remote-root-a".into(),
            etag: "\"parent-v1\"".into(),
            byte_len: 0,
        },
    }
}
fn local(name: &str, id: u64) -> LocalNamespaceEntry {
    LocalNamespaceEntry {
        parent: parent(),
        name: name.into(),
        local_file: LocalFileIdentity {
            volume_serial: 7,
            file_index: id,
        },
        object_kind: NamespaceObjectKind::File,
    }
}
fn source() -> ExistingNamespaceEntry {
    ExistingNamespaceEntry {
        local: local("source.txt", 13),
        remote: RemoteEditBaseline {
            resource_id: "remote-file-a".into(),
            etag: "\"file-v1\"".into(),
            byte_len: 4,
        },
    }
}
fn content() -> NamespaceFileContent {
    NamespaceFileContent {
        byte_len: 4,
        sha256: "a".repeat(64),
    }
}
fn intent(operation: NamespaceOperation) -> NamespaceIntent {
    NamespaceIntent {
        schema_version: 1,
        record_id: "0123456789abcdef0123456789abcdef".into(),
        record_generation: 2,
        operation,
    }
}
fn event(intent: &NamespaceIntent, seq: u64, event: NamespaceEventKind) -> NamespaceEvent {
    NamespaceEvent {
        context: intent.event_context().unwrap(),
        sequence: seq,
        event,
    }
}
fn report(
    destination: LocalNamespaceEntry,
    resource: &str,
    payload: Option<NamespaceFileContent>,
) -> NamespaceDestinationReport {
    NamespaceDestinationReport {
        destination,
        remote: RemoteEditBaseline {
            resource_id: resource.into(),
            etag: "\"result-v2\"".into(),
            byte_len: payload.as_ref().map_or(4, |p| p.byte_len),
        },
        content: payload,
    }
}
fn copy_intent() -> NamespaceIntent {
    let mut dest = local("copy.txt", 14);
    dest.parent.scope.space_id = "shared-b".into();
    dest.parent.scope.account_subject = "account-b".into();
    dest.parent.scope.profile_id = "profile-b".into();
    dest.parent.authorization.agent_generation = 9;
    intent(NamespaceOperation::CopyThenRemove {
        source: source(),
        destination: dest,
        content: content(),
    })
}
#[test]
fn all_operation_shapes_validate_without_enabling_an_operation() {
    let src = source();
    let dest = local("renamed.txt", 13);
    let mut dir = local("new-folder", 14);
    dir.object_kind = NamespaceObjectKind::Directory;
    let mut existing_dir = src.clone();
    existing_dir.local.object_kind = NamespaceObjectKind::Directory;
    let mut replacement = src.local.clone();
    replacement.local_file.file_index = 15;
    let ops = vec![
        NamespaceOperation::CreateFile {
            destination: local("new.txt", 14),
            content: content(),
        },
        NamespaceOperation::CreateDirectory { destination: dir },
        NamespaceOperation::ReplaceContents {
            source: src.clone(),
            content: content(),
        },
        NamespaceOperation::AtomicReplacement {
            source: src.clone(),
            replacement,
            content: content(),
        },
        NamespaceOperation::MoveWithinScope {
            source: src.clone(),
            destination: dest,
        },
        NamespaceOperation::DeleteFile { source: src },
        NamespaceOperation::DeleteDirectory {
            source: existing_dir,
        },
    ];
    for op in ops {
        let record = intent(op);
        record.validate().unwrap();
        let parsed: NamespaceIntent =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        let progress = NamespaceIntentProgress::new(parsed).unwrap();
        assert_eq!(progress.snapshot().remote, NamespacePhase::Pending);
        assert!(!progress.snapshot().recorded_complete);
    }
    copy_intent().validate().unwrap();
}
#[test]
fn in_place_completion_requires_both_matching_remote_and_local_reports() {
    let i = intent(NamespaceOperation::ReplaceContents {
        source: source(),
        content: content(),
    });
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
        .unwrap();
    p.record(&event(
        &i,
        2,
        NamespaceEventKind::RemoteVerified {
            report: report(source().local, "remote-file-a", Some(content())),
        },
    ))
    .unwrap();
    assert!(!p.snapshot().local_completed);
    assert!(!p.snapshot().recorded_complete);
    p.record(&event(
        &i,
        3,
        NamespaceEventKind::LocalCompleted {
            destination: source().local,
        },
    ))
    .unwrap();
    assert!(p.snapshot().recorded_complete);
    assert!(
        p.record(&event(&i, 4, NamespaceEventKind::RemoteSubmitted))
            .is_err()
    );
}
#[test]
fn local_completed_never_implies_remote_verified() {
    let i = intent(NamespaceOperation::CreateFile {
        destination: local("new.txt", 14),
        content: content(),
    });
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    p.record(&event(
        &i,
        1,
        NamespaceEventKind::LocalCompleted {
            destination: local("new.txt", 14),
        },
    ))
    .unwrap();
    assert!(p.snapshot().local_completed);
    assert_eq!(p.snapshot().remote, NamespacePhase::Pending);
    assert!(!p.snapshot().recorded_complete);
}
#[test]
fn event_context_refuses_stale_record_agent_token_root_and_parent_identity() {
    let i = copy_intent();
    let e = event(&i, 1, NamespaceEventKind::RemoteSubmitted);
    for case in 0..8 {
        let mut wrong = e.clone();
        match case {
            0 => wrong.context.record_generation += 1,
            1 => {
                wrong
                    .context
                    .source_parent
                    .as_mut()
                    .unwrap()
                    .authorization
                    .agent_generation += 1
            }
            2 => {
                wrong
                    .context
                    .destination_parent
                    .as_mut()
                    .unwrap()
                    .authorization
                    .token_generation += 1
            }
            3 => {
                wrong
                    .context
                    .source_parent
                    .as_mut()
                    .unwrap()
                    .scope
                    .root_file_index += 1
            }
            4 => {
                wrong
                    .context
                    .destination_parent
                    .as_mut()
                    .unwrap()
                    .local_file
                    .file_index += 1
            }
            5 => {
                wrong
                    .context
                    .destination_parent
                    .as_mut()
                    .unwrap()
                    .remote
                    .resource_id = "different-parent".into()
            }
            6 => {
                wrong
                    .context
                    .source_parent
                    .as_mut()
                    .unwrap()
                    .scope
                    .account_subject = "other-account".into()
            }
            _ => wrong.context.intent_sha256 = "0".repeat(64),
        };
        let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
        assert_eq!(p.record(&wrong), Err(NamespaceIntentError::ScopeMismatch));
        assert_eq!(p.snapshot().sequence, 0);
    }
}
#[test]
fn matching_record_id_does_not_allow_evidence_for_changed_file_or_baseline() {
    let i = intent(NamespaceOperation::ReplaceContents {
        source: source(),
        content: content(),
    });
    let mut changed = i.clone();
    if let NamespaceOperation::ReplaceContents { source, .. } = &mut changed.operation {
        source.local.local_file.file_index += 1;
        source.remote.etag = "\"another\"".into();
    }
    let e = event(&changed, 1, NamespaceEventKind::RemoteSubmitted);
    let mut p = NamespaceIntentProgress::new(i).unwrap();
    assert_eq!(p.record(&e), Err(NamespaceIntentError::ScopeMismatch));
}
#[test]
fn atomic_replacement_cannot_reuse_old_local_identity_or_complete_wrong_file() {
    let src = source();
    let mut replacement = src.local.clone();
    let bad = intent(NamespaceOperation::AtomicReplacement {
        source: src.clone(),
        replacement: replacement.clone(),
        content: content(),
    });
    assert!(bad.validate().is_err());
    replacement.local_file.file_index = 90;
    let i = intent(NamespaceOperation::AtomicReplacement {
        source: src.clone(),
        replacement: replacement.clone(),
        content: content(),
    });
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    assert_eq!(
        p.record(&event(
            &i,
            1,
            NamespaceEventKind::LocalCompleted {
                destination: src.local
            }
        )),
        Err(NamespaceIntentError::EvidenceMismatch)
    );
    p.record(&event(
        &i,
        1,
        NamespaceEventKind::LocalCompleted {
            destination: replacement,
        },
    ))
    .unwrap();
    assert!(!p.snapshot().recorded_complete);
}
#[test]
fn ordinary_labels_never_allow_encrypted_or_unknown_parent_records() {
    for classification in [
        StorageClassification::Unknown,
        StorageClassification::Encrypted,
    ] {
        let mut target = local("new.txt", 14);
        target.parent.classification = classification;
        let i = intent(NamespaceOperation::CreateFile {
            destination: target,
            content: content(),
        });
        assert_eq!(
            i.validate(),
            Err(NamespaceIntentError::StorageClassificationUnavailable)
        );
        assert!(NamespaceIntentProgress::new(i).is_err());
    }
}
#[test]
fn move_is_same_scope_same_file_identity_only() {
    for field in 0..5 {
        let mut dest = local("renamed.txt", 13);
        match field {
            0 => dest.parent.scope.space_id = "other-space".into(),
            1 => dest.parent.scope.account_subject = "other-account".into(),
            2 => dest.parent.scope.root_file_index += 1,
            3 => dest.local_file.file_index += 1,
            _ => dest.parent.authorization.token_generation += 1,
        };
        assert!(
            intent(NamespaceOperation::MoveWithinScope {
                source: source(),
                destination: dest
            })
            .validate()
            .is_err()
        );
    }
}
#[test]
fn copied_source_removal_requires_exact_destination_content_and_local_completion() {
    let i = copy_intent();
    let dest = i.operation.destination().unwrap().clone();
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    let remove = NamespaceEventKind::SourceRemovalSubmitted { source: source() };
    assert!(p.record(&event(&i, 1, remove.clone())).is_err());
    p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
        .unwrap();
    for field in 0..5 {
        let mut wrong = report(dest.clone(), "copied-resource", Some(content()));
        match field {
            0 => wrong.destination.local_file.file_index += 1,
            1 => wrong.destination.parent.remote.resource_id = "wrong-parent".into(),
            2 => wrong.content.as_mut().unwrap().sha256 = "b".repeat(64),
            3 => wrong.remote.byte_len += 1,
            _ => wrong.remote.etag = "W/\"weak\"".into(),
        };
        assert!(
            p.record(&event(
                &i,
                2,
                NamespaceEventKind::RemoteVerified { report: wrong }
            ))
            .is_err()
        );
        assert_eq!(p.snapshot().remote, NamespacePhase::Submitted);
    }
    p.record(&event(
        &i,
        2,
        NamespaceEventKind::RemoteVerified {
            report: report(dest.clone(), "copied-resource", Some(content())),
        },
    ))
    .unwrap();
    assert!(p.record(&event(&i, 3, remove.clone())).is_err());
    p.record(&event(
        &i,
        3,
        NamespaceEventKind::LocalCompleted { destination: dest },
    ))
    .unwrap();
    p.record(&event(&i, 4, remove)).unwrap();
    assert!(!p.snapshot().recorded_complete);
    let mut wrong = source();
    wrong.remote.etag = "\"replaced-source\"".into();
    assert!(
        p.record(&event(
            &i,
            5,
            NamespaceEventKind::SourceRemovalVerified { source: wrong }
        ))
        .is_err()
    );
    p.record(&event(
        &i,
        5,
        NamespaceEventKind::SourceRemovalVerified { source: source() },
    ))
    .unwrap();
    assert!(p.snapshot().recorded_complete);
}
#[test]
fn explicit_delete_is_not_provider_cleanup_or_copy_source_removal() {
    let i = intent(NamespaceOperation::DeleteFile { source: source() });
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    assert!(
        p.record(&event(
            &i,
            1,
            NamespaceEventKind::SourceRemovalSubmitted { source: source() }
        ))
        .is_err()
    );
    p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
        .unwrap();
    p.record(&event(
        &i,
        2,
        NamespaceEventKind::RemoteDeleted { source: source() },
    ))
    .unwrap();
    assert!(!p.snapshot().recorded_complete);
    p.record(&event(
        &i,
        3,
        NamespaceEventKind::LocalDeleted { source: source() },
    ))
    .unwrap();
    assert!(p.snapshot().recorded_complete);
    assert!(
        serde_json::from_value::<NamespaceOperation>(
            serde_json::json!({"kind":"internal_cleanup","source":source()})
        )
        .is_err()
    );
}
#[test]
fn uncertainty_conflict_and_deferral_cannot_be_cleared_by_a_success_event() {
    for fault in [
        NamespaceEventKind::Uncertain,
        NamespaceEventKind::Conflict,
        NamespaceEventKind::Deferred,
    ] {
        let i = intent(NamespaceOperation::CreateFile {
            destination: local("new.txt", 14),
            content: content(),
        });
        let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
        p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
            .unwrap();
        p.record(&event(&i, 2, fault)).unwrap();
        let before = p.snapshot();
        let forged = event(
            &i,
            3,
            NamespaceEventKind::RemoteVerified {
                report: report(local("new.txt", 14), "created", Some(content())),
            },
        );
        assert!(p.record(&forged).is_err());
        assert_eq!(p.snapshot(), before);
        assert!(!before.recorded_complete);
    }
}
#[test]
fn malformed_fields_components_and_root_only_adoption_fail_closed() {
    for name in [
        "..", ".", "a/b", "a\\b", "a:b", "NUL.txt", "COM1", "bad.", "bad ", "a\n",
    ] {
        let i = intent(NamespaceOperation::CreateFile {
            destination: local(name, 14),
            content: content(),
        });
        assert!(i.validate().is_err());
    }
    for field in 0..10 {
        let mut dest = local("new.txt", 14);
        match field {
            0 => dest.parent.local_components.clear(),
            1 => dest.local_file.file_index = 0,
            2 => dest.local_file.volume_serial = 88,
            3 => dest.parent.local_file.file_index = 11,
            4 => dest.parent.scope.server_origin = "http://cloud.example.test".into(),
            5 => {
                dest.parent.scope.server_origin = "https://user:password@cloud.example.test".into()
            }
            6 => dest.parent.remote.etag = "*".into(),
            7 => dest.parent.local_components = vec!["a".into(); 256],
            8 => dest.name = "x".repeat(256),
            _ => dest.parent.remote.resource_id.clear(),
        };
        assert!(
            intent(NamespaceOperation::CreateFile {
                destination: dest,
                content: content()
            })
            .validate()
            .is_err()
        );
    }
    let mut bad = source();
    bad.remote.resource_id = bad.local.parent.scope.root_resource_id.clone();
    assert!(
        intent(NamespaceOperation::DeleteFile { source: bad })
            .validate()
            .is_err()
    );
}
#[test]
fn malformed_serialized_metadata_and_out_of_order_events_are_not_accepted() {
    let i = intent(NamespaceOperation::CreateFile {
        destination: local("new.txt", 14),
        content: content(),
    });
    let mut value = serde_json::to_value(&i).unwrap();
    value["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<NamespaceIntent>(value).is_err());
    let mut value = serde_json::to_value(&i).unwrap();
    value["record_generation"] = serde_json::json!(0);
    let parsed: NamespaceIntent = serde_json::from_value(value).unwrap();
    assert!(NamespaceIntentProgress::new(parsed).is_err());
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    assert!(
        p.record(&event(&i, 2, NamespaceEventKind::RemoteSubmitted))
            .is_err()
    );
    assert_eq!(p.snapshot().sequence, 0);
    p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
        .unwrap();
    assert!(
        p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
            .is_err()
    );
    assert_eq!(p.snapshot().sequence, 1);
}
#[test]
fn debug_redacts_paths_accounts_and_content_fingerprints() {
    let i = copy_intent();
    let text = format!("{i:?}");
    assert!(!text.contains("account-a"));
    assert!(!text.contains("source.txt"));
    assert!(!text.contains(&"a".repeat(64)));
}

#[test]
fn destination_reports_cannot_adopt_a_parent_or_root_remote_identity() {
    let destination = local("new.txt", 14);
    let i = intent(NamespaceOperation::CreateFile {
        destination: destination.clone(),
        content: content(),
    });
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
        .unwrap();
    for resource in [
        destination.parent.remote.resource_id.as_str(),
        destination.parent.scope.root_resource_id.as_str(),
    ] {
        assert_eq!(
            p.record(&event(
                &i,
                2,
                NamespaceEventKind::RemoteVerified {
                    report: report(destination.clone(), resource, Some(content()))
                }
            )),
            Err(NamespaceIntentError::EvidenceMismatch)
        );
        assert_eq!(p.snapshot().sequence, 1);
    }
}

#[test]
fn copy_then_remove_rejects_same_remote_path_across_profile_aliases() {
    let src = source();
    for field in 0..3 {
        let mut destination = src.local.clone();
        destination.local_file.file_index = 99;
        // Distinct root/parent local identities can still refer to the same
        // remote parent through a second profile.
        destination.parent.scope.profile_id = "alias-profile".into();
        destination.parent.scope.root_file_index = 50;
        destination.parent.local_file.file_index = 51;
        match field {
            0 => (),
            1 => destination.parent.authorization.agent_generation += 1,
            _ => destination.name = "SOURCE.TXT".into(),
        }
        assert_eq!(
            intent(NamespaceOperation::CopyThenRemove {
                source: src.clone(),
                destination,
                content: content(),
            })
            .validate(),
            Err(NamespaceIntentError::ScopeMismatch)
        );
    }
}

#[test]
fn copy_verification_cannot_reuse_source_resource_in_same_remote_namespace() {
    let destination = local("copy.txt", 14);
    let i = intent(NamespaceOperation::CopyThenRemove {
        source: source(),
        destination: destination.clone(),
        content: content(),
    });
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
        .unwrap();
    assert_eq!(
        p.record(&event(
            &i,
            2,
            NamespaceEventKind::RemoteVerified {
                report: report(destination, "remote-file-a", Some(content()))
            }
        )),
        Err(NamespaceIntentError::EvidenceMismatch)
    );
    assert_eq!(p.snapshot().remote, NamespacePhase::Submitted);
    assert_eq!(p.snapshot().source_removal, Some(NamespacePhase::Pending));
}

#[test]
fn move_preserves_identity_and_requires_destination_then_source_absence_reports() {
    let destination = local("renamed.txt", 13);
    let i = intent(NamespaceOperation::MoveWithinScope {
        source: source(),
        destination: destination.clone(),
    });
    let mut p = NamespaceIntentProgress::new(i.clone()).unwrap();
    let removed = NamespaceEventKind::SourceRemovalVerified { source: source() };
    assert!(p.record(&event(&i, 1, removed.clone())).is_err());
    p.record(&event(&i, 1, NamespaceEventKind::RemoteSubmitted))
        .unwrap();
    p.record(&event(
        &i,
        2,
        NamespaceEventKind::RemoteVerified {
            report: report(destination.clone(), "remote-file-a", None),
        },
    ))
    .unwrap();
    assert!(p.record(&event(&i, 3, removed.clone())).is_err());
    p.record(&event(
        &i,
        3,
        NamespaceEventKind::LocalCompleted { destination },
    ))
    .unwrap();
    assert!(!p.snapshot().recorded_complete);
    p.record(&event(&i, 4, removed)).unwrap();
    assert!(p.snapshot().recorded_complete);
}

#[test]
fn directory_move_rejects_known_case_alias_descendant_paths() {
    let mut src = source();
    src.local.object_kind = NamespaceObjectKind::Directory;
    src.local.name = "Folder".into();
    for parts in [
        vec!["Personal", "Folder"],
        vec!["PERSONAL", "folder", "child"],
    ] {
        let mut destination = src.local.clone();
        destination.name = "Moved".into();
        destination.parent.local_file.file_index = 77;
        destination.parent.local_components = parts.into_iter().map(String::from).collect();
        destination.parent.remote.resource_id = "descendant".into();
        assert_eq!(
            intent(NamespaceOperation::MoveWithinScope {
                source: src.clone(),
                destination,
            })
            .validate(),
            Err(NamespaceIntentError::ScopeMismatch)
        );
    }
}
