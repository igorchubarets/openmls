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
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, PrivateMessage},
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
        .export_message_secrets_store(&group_key, provider.crypto())
        .expect("Error exporting message secrets.");

    let plaintext = decrypt_application_message_with_stored_secrets(
        &blob,
        &group_key,
        &msg_bytes,
        ciphersuite,
        provider.crypto(),
    )
    .expect("Own message should decrypt from own stored secrets via key_enc.");
    assert_eq!(plaintext, b"hello from alice");

    // Idempotent: nothing is consumed, so re-decryption works again.
    let plaintext_again = decrypt_application_message_with_stored_secrets(
        &blob,
        &group_key,
        &msg_bytes,
        ciphersuite,
        provider.crypto(),
    )
    .expect("Re-decryption must be idempotent.");
    assert_eq!(plaintext_again, b"hello from alice");
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
            .export_message_secrets_store(&group_key, provider.crypto())
            .expect("Error exporting message secrets.");
        let plaintext = decrypt_application_message_with_stored_secrets(
            &blob,
            &group_key,
            &msg_bytes,
            ciphersuite,
            provider.crypto(),
        )
        .expect("Every member's blob must decrypt the same message.");
        assert_eq!(plaintext, b"shared secret");
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
        .export_message_secrets_store(&group_key, provider.crypto())
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
            &tampered_bytes,
            ciphersuite,
            provider.crypto(),
        )
        .is_err(),
        "Tampered key_enc must not decrypt."
    );
}

/// A message without `key_enc` (legacy) still decrypts via the stored ratchet
/// path, as before.
#[openmls_test::openmls_test]
fn legacy_message_without_key_enc_uses_ratchet_path() {
    let provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (_alice_credential, bob_credential, mut alice_group, mut bob_group) =
        setup_two_member_group(ciphersuite, provider, bob_provider);
    let group_key = vec![0u8; ciphersuite.aead_key_length()];

    let bob_msg = bob_group
        .create_message(provider, &bob_credential.signer, b"from bob")
        .expect("Error creating message.");
    let legacy_bytes = with_key_enc(&bob_msg, Vec::new());

    let alice_blob = alice_group
        .export_message_secrets_store(&group_key, provider.crypto())
        .expect("Error exporting message secrets.");
    let plaintext = decrypt_application_message_with_stored_secrets(
        &alice_blob,
        &group_key,
        &legacy_bytes,
        ciphersuite,
        provider.crypto(),
    )
    .expect("Legacy message must decrypt via the stored ratchet path.");
    assert_eq!(plaintext, b"from bob");
}
