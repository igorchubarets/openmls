//! Tests for stored-secrets decryption with the per-message `key_enc`
//! extension.
//!
//! `decrypt_application_message_with_stored_secrets` decrypts an application
//! message from an exported epoch-secret blob without any live group state.
//! With the `key_enc` extension (the sender's wrapped content key material
//! carried inside the message) this works for the sender's OWN messages too —
//! previously a `RatchetTypeError`, since the stored secret tree holds an
//! encryption ratchet for the own leaf — and is idempotent, since nothing is
//! consumed.

use crate::{
    framing::{
        mls_auth_content::AuthenticatedContent, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
        PrivateMessage,
    },
    group::decrypt_application_message_with_stored_secrets,
    prelude::{
        tests_and_kats::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
        *,
    },
    test_utils::frankenstein::FrankenPrivateMessage,
    versions::ProtocolVersion,
};
use tls_codec::{Deserialize, Serialize};

/// Set up a two-member group (Alice owns it, Bob joins via the welcome).
/// Each member uses their own provider, as storage is per-member.
fn setup_two_member_group<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    alice_provider: &Provider,
    bob_provider: &Provider,
) -> (CredentialWithKeyAndSigner, CredentialWithKeyAndSigner, MlsGroup, MlsGroup) {
    let alice_credential = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let bob_credential = generate_credential_with_key(
        b"Bob".to_vec(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    // Alice creates a group and adds Bob.
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_credential.signer,
        &mls_group_create_config,
        alice_credential.credential_with_key.clone(),
    )
    .expect("Error creating Alice's group.");
    let bob_key_package_bundle = KeyPackageBundle::generate(
        bob_provider,
        &bob_credential.signer,
        ciphersuite,
        bob_credential.credential_with_key.clone(),
    );
    let (commit, welcome, _) = alice_group
        .add_members(
            alice_provider,
            &alice_credential.signer,
            core::slice::from_ref(bob_key_package_bundle.key_package()),
        )
        .expect("Error adding Bob.");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("Error merging commit.");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().expect("expected a welcome");
    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating staged join from Welcome")
    .into_group(bob_provider)
    .expect("Error creating group from staged join");

    // Bob is a member of the same epoch as Alice.
    debug_assert_eq!(alice_group.epoch(), bob_group.epoch());
    let _ = commit;

    (alice_credential, bob_credential, alice_group, bob_group)
}

/// Re-serialize a message, replacing its `key_enc` bytes (e.g. empty for a
/// legacy message, or garbage for a tamper test).
fn with_key_enc(msg: &MlsMessageOut, key_enc: Vec<u8>) -> Vec<u8> {
    let msg_in =
        MlsMessageIn::tls_deserialize_exact(&msg.tls_serialize_detached().unwrap()).unwrap();
    let private = match msg_in.extract() {
        MlsMessageBodyIn::PrivateMessage(p) => p,
        _ => panic!("expected a private message"),
    };
    let mut franken: FrankenPrivateMessage = PrivateMessage::from(private).into();
    franken.key_enc = key_enc.into();
    let restored: PrivateMessage = franken.into();
    MlsMessageOut::from_private_message(restored, ProtocolVersion::Mls10)
        .tls_serialize_detached()
        .unwrap()
}

/// The core fix: a member's OWN application message decrypts from their own
/// epoch-secret blob via `key_enc` (previously `RatchetTypeError`), and
/// repeated decryption is idempotent.
#[openmls_test::openmls_test]
fn own_message_decrypts_from_stored_secrets() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, _bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let msg = alice_group
        .create_message(provider, &alice_credential.signer, b"hello from alice")
        .expect("Error creating message.");
    let msg_bytes = msg.tls_serialize_detached().unwrap();
    let blob = alice_group
        .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
        .expect("Error exporting message secrets.");

    let plaintext = decrypt_application_message_with_stored_secrets(
        &blob,
        &group_key,
        alice_group.group_id().as_slice(),
        alice_group.epoch().as_u64(),
        1,
        &msg_bytes,
        ciphersuite,
        provider.crypto(),
    )
    .expect("Own message should decrypt from own stored secrets via key_enc.");
    assert_eq!(plaintext.0, b"hello from alice");
    assert_eq!(
        plaintext.1,
        alice_credential
            .credential_with_key
            .credential
            .serialized_content()
    );

    // Idempotent: nothing is consumed, so re-decryption works again.
    let plaintext_again = decrypt_application_message_with_stored_secrets(
        &blob,
        &group_key,
        alice_group.group_id().as_slice(),
        alice_group.epoch().as_u64(),
        1,
        &msg_bytes,
        ciphersuite,
        provider.crypto(),
    )
    .expect("Re-decryption must be idempotent.");
    assert_eq!(plaintext_again.0, b"hello from alice");
    assert_eq!(plaintext_again.1, plaintext.1);
}

/// The wrap key is epoch-deterministic across members, so every member's own
/// blob decrypts the same message — each member's leaf state is irrelevant.
#[openmls_test::openmls_test]
fn every_members_blob_decrypts_the_message() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, _bob_credential, mut alice_group, bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let msg = alice_group
        .create_message(provider, &alice_credential.signer, b"shared secret")
        .expect("Error creating message.");
    let msg_bytes = msg.tls_serialize_detached().unwrap();

    for group in [&alice_group, &bob_group] {
        let blob = group
            .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
            .expect("Error exporting message secrets.");
        let plaintext = decrypt_application_message_with_stored_secrets(
            &blob,
            &group_key,
            group.group_id().as_slice(),
            group.epoch().as_u64(),
            1,
            &msg_bytes,
            ciphersuite,
            provider.crypto(),
        )
        .expect("Every member's blob must decrypt the same message.");
        assert_eq!(plaintext.0, b"shared secret");
    }
}

/// Tampering with `key_enc` is detected by the wrap AEAD — an error, never
/// plaintext.
#[openmls_test::openmls_test]
fn tampered_key_enc_rejected() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, _bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let msg = alice_group
        .create_message(provider, &alice_credential.signer, b"secret")
        .expect("Error creating message.");
    let blob = alice_group
        .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
        .expect("Error exporting message secrets.");

    // The original key_enc is opaque; grab its length to craft a same-length
    // tampered replacement.
    let msg_in =
        MlsMessageIn::tls_deserialize_exact(&msg.tls_serialize_detached().unwrap()).unwrap();
    let private = match msg_in.extract() {
        MlsMessageBodyIn::PrivateMessage(p) => p,
        _ => panic!("expected a private message"),
    };
    let franken: FrankenPrivateMessage = PrivateMessage::from(private).into();
    let key_enc_len = franken.key_enc.as_slice().len();
    assert!(key_enc_len > 0);

    let mut tampered = vec![0u8; key_enc_len];
    tampered[0] ^= 0xff;
    let tampered_bytes = with_key_enc(&msg, tampered);
    assert!(
        decrypt_application_message_with_stored_secrets(
            &blob,
            &group_key,
            alice_group.group_id().as_slice(),
            alice_group.epoch().as_u64(),
            1,
            &tampered_bytes,
            ciphersuite,
            provider.crypto(),
        )
        .is_err(),
        "Tampered key_enc must not decrypt."
    );
}

/// Epoch exports use a fresh nonce and bind room, epoch, and key version in
/// the AAD.
#[openmls_test::openmls_test]
fn archive_exports_use_fresh_nonce_and_aad_binding() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, _bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let msg = alice_group
        .create_message(provider, &alice_credential.signer, b"aad-bound")
        .expect("Error creating message.");
    let msg_bytes = msg.tls_serialize_detached().expect("serialize");
    let blob_a = alice_group
        .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
        .expect("export a");
    let blob_b = alice_group
        .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
        .expect("export b");

    let magic = crate::group::mls_group::past_secrets::HISTORY_ENVELOPE_MAGIC;
    let nonce_len = ciphersuite.aead_nonce_length();
    assert_ne!(blob_a, blob_b, "fresh exports must differ");
    assert_ne!(
        blob_a[magic.len()..magic.len() + nonce_len],
        blob_b[magic.len()..magic.len() + nonce_len],
        "nonces must be fresh per export"
    );

    let group_id = alice_group.group_id().as_slice().to_vec();
    let epoch = alice_group.epoch().as_u64();
    for (wrong_group, wrong_epoch, wrong_version) in [
        (b"other-group".as_slice(), epoch, 1),
        (group_id.as_slice(), epoch + 1, 1),
        (group_id.as_slice(), epoch, 2),
    ] {
        assert!(
            decrypt_application_message_with_stored_secrets(
                &blob_a,
                &group_key,
                wrong_group,
                wrong_epoch,
                wrong_version,
                &msg_bytes,
                ciphersuite,
                provider.crypto(),
            )
            .is_err(),
            "wrong AAD must fail"
        );
    }

    let plaintext = decrypt_application_message_with_stored_secrets(
        &blob_a,
        &group_key,
        &group_id,
        epoch,
        1,
        &msg_bytes,
        ciphersuite,
        provider.crypto(),
    )
    .expect("correct AAD must decrypt");
    assert_eq!(plaintext.0, b"aad-bound");
}

/// Pre-launch hardening: unversioned archives and application messages without
/// key_enc are rejected; there is no legacy ratchet fallback.
#[openmls_test::openmls_test]
fn unversioned_archive_and_empty_key_enc_rejected() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, _bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let msg = alice_group
        .create_message(provider, &alice_credential.signer, b"no legacy")
        .expect("Error creating message.");
    let msg_bytes = msg.tls_serialize_detached().expect("serialize");
    let blob = alice_group
        .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
        .expect("export");

    let mut unversioned = blob.clone();
    unversioned[0] ^= 0xff;
    assert!(
        decrypt_application_message_with_stored_secrets(
            &unversioned,
            &group_key,
            alice_group.group_id().as_slice(),
            alice_group.epoch().as_u64(),
            1,
            &msg_bytes,
            ciphersuite,
            provider.crypto(),
        )
        .is_err(),
        "unversioned archive must fail closed"
    );

    let missing_key_enc = with_key_enc(&msg, Vec::new());
    assert!(
        decrypt_application_message_with_stored_secrets(
            &blob,
            &group_key,
            alice_group.group_id().as_slice(),
            alice_group.epoch().as_u64(),
            1,
            &missing_key_enc,
            ciphersuite,
            provider.crypto(),
        )
        .is_err(),
        "application message without key_enc must fail closed"
    );
}

/// A member cannot attribute an application message to another member by
/// signing it with their own leaf key. The MLS signature must match the inner
/// sender leaf before plaintext is returned, on both live and stored-secrets
/// paths.
#[openmls_test::openmls_test]
fn forged_sender_signature_rejected_in_live_and_stored_paths() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    // Claim Alice's leaf index, but sign with Bob's key.
    let forged = AuthenticatedContent::new_application(
        LeafNodeIndex::new(0),
        &[],
        b"forged as alice",
        alice_group.export_group_context(),
        &bob_credential.signer,
    )
    .expect("Could not build forged application content.");

    let forged_private = PrivateMessage::encrypt_without_check::<<Provider as crate::storage::OpenMlsProvider>::StorageError>(
        provider.crypto(),
        provider.rand(),
        &forged,
        ciphersuite,
        alice_group.message_secrets_test_mut(),
        0,
    )
    .expect("Could not encrypt forged application content.");
    let forged_bytes = MlsMessageOut::from_private_message(forged_private, ProtocolVersion::Mls10)
        .tls_serialize_detached()
        .expect("Could not serialize forged message.");

    let blob = alice_group
        .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
        .expect("Error exporting message secrets.");

    assert!(
        decrypt_application_message_with_stored_secrets(
            &blob,
            &group_key,
            alice_group.group_id().as_slice(),
            alice_group.epoch().as_u64(),
            1,
            &forged_bytes,
            ciphersuite,
            provider.crypto(),
        )
        .is_err(),
        "Stored-secrets path accepted a forged sender signature."
    );
    assert!(
        alice_group
            .decrypt_application_message_with_live_secrets(&forged_bytes, provider.crypto())
            .is_err(),
        "Live-secrets path accepted a forged sender signature."
    );

    let _ = alice_credential;
}


