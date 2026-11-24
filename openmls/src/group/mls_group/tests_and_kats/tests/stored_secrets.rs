//! Tests for stored-secrets decryption with the versioned history blob.
//!
//! `decrypt_application_message_with_stored_secrets` decrypts an application
//! message from an exported epoch-secret blob without any live group state.
//! The signed history blob in MLS authenticated data carries the wrapped MLS
//! content key, so this works for the sender's OWN messages too and is
//! idempotent because nothing is consumed.

use crate::{
    framing::{
        history::{decode_history_blob, encode_history_blob},
        MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, PrivateMessage,
    },
    group::{
        decrypt_application_message_with_epoch_archive,
        decrypt_application_message_with_stored_secrets,
    },
    prelude::{
        tests_and_kats::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
        *,
    },
    test_utils::frankenstein::FrankenPrivateMessage,
    versions::ProtocolVersion,
};
use tls_codec::{Deserialize, Serialize};

fn replay_id(seq: u64) -> Vec<u8> {
    format!("yourn-replay-v1|{seq}").into_bytes()
}

fn history_blob_of(msg: &MlsMessageOut) -> Vec<u8> {
    let msg_in =
        MlsMessageIn::tls_deserialize_exact(&msg.tls_serialize_detached().unwrap()).unwrap();
    match msg_in.extract() {
        MlsMessageBodyIn::PrivateMessage(p) => p.aad().to_vec(),
        _ => panic!("expected a private message"),
    }
}

fn key_enc_of(msg: &MlsMessageOut) -> Vec<u8> {
    decode_history_blob(&history_blob_of(msg))
        .expect("valid history blob")
        .key_enc
}

fn with_aad(msg: &MlsMessageOut, aad: Vec<u8>) -> Vec<u8> {
    let msg_in =
        MlsMessageIn::tls_deserialize_exact(&msg.tls_serialize_detached().unwrap()).unwrap();
    let private = match msg_in.extract() {
        MlsMessageBodyIn::PrivateMessage(p) => p,
        _ => panic!("expected a private message"),
    };
    let mut franken: FrankenPrivateMessage = PrivateMessage::from(private).into();
    franken.authenticated_data = aad.into();
    let restored: PrivateMessage = franken.into();
    MlsMessageOut::from_private_message(restored, ProtocolVersion::Mls10)
        .tls_serialize_detached()
        .unwrap()
}

fn with_history_key_enc(msg: &MlsMessageOut, key_enc: Vec<u8>) -> Vec<u8> {
    let mut history = decode_history_blob(&history_blob_of(msg)).expect("valid history blob");
    history.key_enc = key_enc;
    with_aad(
        msg,
        encode_history_blob(&history.replay_id, &history.key_enc),
    )
}

fn with_history_replay_id(msg: &MlsMessageOut, replay_id: Vec<u8>) -> Vec<u8> {
    let mut history = decode_history_blob(&history_blob_of(msg)).expect("valid history blob");
    history.replay_id = replay_id;
    with_aad(
        msg,
        encode_history_blob(&history.replay_id, &history.key_enc),
    )
}

/// Set up a two-member group (Alice owns it, Bob joins via the welcome).
/// Each member uses their own provider, as storage is per-member.
fn setup_two_member_group<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    alice_provider: &Provider,
    bob_provider: &Provider,
) -> (
    CredentialWithKeyAndSigner,
    CredentialWithKeyAndSigner,
    MlsGroup,
    MlsGroup,
) {
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

/// The core fix: a member's OWN application message decrypts from their own
/// epoch-secret blob via the history key envelope (previously
/// `RatchetTypeError`), and repeated decryption is idempotent.
#[openmls_test::openmls_test]
fn own_message_decrypts_from_stored_secrets() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, _bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let msg = alice_group
        .create_message_with_history(
            provider,
            &alice_credential.signer,
            b"hello from alice",
            &replay_id(1),
        )
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
        .create_message_with_history(
            provider,
            &alice_credential.signer,
            b"shared secret",
            &replay_id(2),
        )
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
        .create_message_with_history(provider, &alice_credential.signer, b"secret", &replay_id(3))
        .expect("Error creating message.");
    let blob = alice_group
        .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
        .expect("Error exporting message secrets.");

    // The wrapped key is opaque; craft a same-length tampered replacement.
    let key_enc_len = key_enc_of(&msg).len();
    assert!(key_enc_len > 0);
    let mut tampered = vec![0u8; key_enc_len];
    tampered[0] ^= 0xff;
    let tampered_bytes = with_history_key_enc(&msg, tampered);
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
        .create_message_with_history(
            provider,
            &alice_credential.signer,
            b"aad-bound",
            &replay_id(4),
        )
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
/// a valid history blob are rejected; there is no legacy ratchet fallback.
#[openmls_test::openmls_test]
fn unversioned_archive_and_missing_history_blob_rejected() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, _bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let msg = alice_group
        .create_message_with_history(
            provider,
            &alice_credential.signer,
            b"no legacy",
            &replay_id(5),
        )
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

    let missing_blob = with_aad(&msg, Vec::new());
    assert!(
        decrypt_application_message_with_stored_secrets(
            &blob,
            &group_key,
            alice_group.group_id().as_slice(),
            alice_group.epoch().as_u64(),
            1,
            &missing_blob,
            ciphersuite,
            provider.crypto(),
        )
        .is_err(),
        "application message without a history blob must fail closed"
    );

    let mut unknown_version = history_blob_of(&msg);
    unknown_version[16] = 0xff;
    let unknown_version = with_aad(&msg, unknown_version);
    assert!(
        decrypt_application_message_with_stored_secrets(
            &blob,
            &group_key,
            alice_group.group_id().as_slice(),
            alice_group.epoch().as_u64(),
            1,
            &unknown_version,
            ciphersuite,
            provider.crypto(),
        )
        .is_err(),
        "unknown history blob version must fail closed"
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
    let (_alice_credential, bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    // Claim Alice's leaf index, but sign with Bob's key.
    let forged = alice_group
        .create_message_with_history(
            provider,
            &bob_credential.signer,
            b"forged as alice",
            &replay_id(6),
        )
        .expect("Could not build forged application content.");
    let forged_bytes = forged
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
}

/// The history key envelope is inside the sender-signed authenticated data. It
/// cannot be transplanted across messages, and changing the replay identity
/// invalidates decryption.
#[openmls_test::openmls_test]
fn history_key_enc_binds_generation_and_replay_id() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, _bob_credential, mut alice_group, _bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let replay_a = replay_id(7);
    let replay_b = replay_id(8);

    let msg_a = alice_group
        .create_message_with_history(
            provider,
            &alice_credential.signer,
            b"bound message",
            &replay_a,
        )
        .expect("create first message");
    let msg_b = alice_group
        .create_message_with_history(
            provider,
            &alice_credential.signer,
            b"bound message",
            &replay_b,
        )
        .expect("create second message");

    let blob = alice_group
        .export_message_secrets_store(&group_key, 1, provider.crypto(), provider.rand())
        .expect("export secrets");
    let decrypt = |ciphertext: &[u8]| {
        decrypt_application_message_with_stored_secrets(
            &blob,
            &group_key,
            alice_group.group_id().as_slice(),
            alice_group.epoch().as_u64(),
            1,
            ciphertext,
            ciphersuite,
            provider.crypto(),
        )
    };

    let (plaintext, _credential, resolved_replay_id) =
        decrypt(&msg_a.tls_serialize_detached().unwrap()).expect("first message decrypts");
    assert_eq!(plaintext, b"bound message");
    assert_eq!(resolved_replay_id, replay_a);

    let transplanted = with_history_key_enc(&msg_a, key_enc_of(&msg_b));
    assert!(
        decrypt(&transplanted).is_err(),
        "key envelope from another ciphertext must fail"
    );

    let tampered_aad = with_history_replay_id(&msg_a, replay_b);
    assert!(
        decrypt(&tampered_aad).is_err(),
        "changing the signed replay identity must fail"
    );
}

/// An immutable epoch archive is identical before and after traffic and
/// decrypts every message from that epoch, including messages sent after the
/// export.
#[openmls_test::openmls_test]
fn epoch_archive_is_stable_and_decrypts_all_messages() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (alice_credential, bob_credential, mut alice_group, bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let commit_id = [7u8; 32];
    let archive_before = alice_group
        .export_epoch_archive_plaintext(&commit_id)
        .expect("Error exporting epoch archive.");
    assert_eq!(
        archive_before,
        bob_group
            .export_epoch_archive_plaintext(&commit_id)
            .expect("Error exporting Bob's epoch archive.")
    );

    let mut messages = Vec::new();
    for (index, body) in [b"first".as_slice(), b"second", b"third"]
        .into_iter()
        .enumerate()
    {
        let message = alice_group
            .create_message_with_history(
                provider,
                &alice_credential.signer,
                body,
                &replay_id(10 + index as u64),
            )
            .expect("Error creating message.");
        messages.push((body.to_vec(), message.tls_serialize_detached().unwrap()));
    }
    let archive_after = alice_group
        .export_epoch_archive_plaintext(&commit_id)
        .expect("Error exporting epoch archive after traffic.");
    assert_eq!(archive_before, archive_after);

    for (body, message) in messages {
        let plaintext = decrypt_application_message_with_epoch_archive(
            &archive_before,
            alice_group.group_id().as_slice(),
            alice_group.epoch().as_u64(),
            &commit_id,
            &message,
            ciphersuite,
            provider.crypto(),
        )
        .expect("Epoch archive must decrypt a later message.");
        assert_eq!(plaintext.0, body);
        assert_eq!(
            plaintext.1,
            alice_credential
                .credential_with_key
                .credential
                .serialized_content()
        );
        let _ = &bob_credential;
    }
}
