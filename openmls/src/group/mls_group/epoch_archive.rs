//! Immutable per-epoch archive used for historical `key_enc` decryption.
//!
//! The archive deliberately contains only epoch-stable data. It never
//! serializes the live `MessageSecretsStore`, the sender ratchet tree, past
//! epochs, or any traffic-dependent state.

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::Ciphersuite;

use crate::ciphersuite::{
    signable::Verifiable, AeadKey, AeadNonce, OpenMlsSignaturePublicKey, Secret,
    SignaturePublicKey,
};
use crate::credentials::{BasicCredential, Credential};
use crate::error::LibraryError;
use crate::framing::{errors::MessageDecryptionError, MlsMessageBodyIn, MlsMessageIn};
use crate::group::errors::ExportSecretsStoreError;
use crate::schedule::message_secrets::key_enc_nonce_from_wrap_key;
use crate::schedule::SenderDataSecret;
use crate::binary_tree::array_representation::LeafNodeIndex;
use tls_codec::Deserialize as _;

use super::*;

pub(crate) const EPOCH_ARCHIVE_MAGIC: &[u8] = b"YRN-EPOCH-ARCHIVE\0";

struct EpochArchiveData {
    ciphersuite: Ciphersuite,
    group_id: Vec<u8>,
    epoch: u64,
    producing_commit_id: Vec<u8>,
    wrap_key: Secret,
    sender_data_secret: SenderDataSecret,
    serialized_context: Vec<u8>,
    leaves: Vec<Member>,
}

impl MlsGroup {
    /// Export the canonical plaintext of the current epoch archive.
    ///
    /// `producing_commit_id` is the canonical commit that created this epoch.
    /// It is not the commit that will later seal the epoch.
    pub fn export_epoch_archive_plaintext(
        &self,
        producing_commit_id: &[u8],
    ) -> Result<Vec<u8>, ExportSecretsStoreError> {
        let secrets = self.message_secrets_store.message_secrets();
        let mut leaves: Vec<Member> = self.public_group().members().collect();
        leaves.sort_by_key(|member| member.index.u32());

        let mut out = Vec::new();
        out.extend_from_slice(EPOCH_ARCHIVE_MAGIC);
        put_u16(&mut out, u16::from(self.ciphersuite()));
        put_bytes(&mut out, self.group_id().as_slice());
        put_u64(&mut out, self.epoch().as_u64());
        put_bytes(&mut out, producing_commit_id);
        put_bytes(&mut out, secrets.wrap_key().as_slice());
        put_bytes(&mut out, secrets.sender_data_secret().archive_bytes());
        put_bytes(&mut out, secrets.serialized_context());
        put_u32(&mut out, leaves.len() as u32);
        for member in leaves {
            let basic = BasicCredential::try_from(member.credential)
                .map_err(|error| ExportSecretsStoreError::Archive(error.to_string()))?;
            put_u32(&mut out, member.index.u32());
            put_bytes(&mut out, &member.signature_key);
            put_bytes(&mut out, basic.identity());
        }
        Ok(out)
    }
}

/// Decrypt an application message from the canonical plaintext of an epoch
/// archive. The caller is responsible for AEAD-decrypting the archive envelope.
pub fn decrypt_application_message_with_epoch_archive(
    archive_plaintext: &[u8],
    expected_group_id: &[u8],
    expected_epoch: u64,
    expected_commit_id: &[u8],
    ciphertext_tls: &[u8],
    ciphersuite: Ciphersuite,
    crypto: &impl OpenMlsCrypto,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), MessageDecryptionError> {
    let archive = decode_epoch_archive(archive_plaintext)
        .map_err(|_| MessageDecryptionError::MalformedContent)?;
    if archive.ciphersuite != ciphersuite
        || archive.group_id != expected_group_id
        || archive.epoch != expected_epoch
        || archive.producing_commit_id != expected_commit_id
        || archive.leaves.is_empty()
    {
        return Err(MessageDecryptionError::MalformedContent);
    }

    let mls_msg = MlsMessageIn::tls_deserialize(&mut &ciphertext_tls[..])
        .map_err(|_| MessageDecryptionError::MalformedContent)?;
    let ciphertext = match mls_msg.extract() {
        MlsMessageBodyIn::PrivateMessage(ct) => ct,
        _ => return Err(MessageDecryptionError::NotApplicationContent),
    };
    if ciphertext.epoch().as_u64() != expected_epoch
        || ciphertext.group_id().as_slice() != expected_group_id
    {
        return Err(MessageDecryptionError::MalformedContent);
    }

    let sender_data = ciphertext.sender_data_with_secret(
        &archive.sender_data_secret,
        crypto,
        ciphersuite,
    )?;
    if !ciphertext.content_type().is_application_message() {
        return Err(MessageDecryptionError::NotApplicationContent);
    }
    if ciphertext.key_enc().is_empty() {
        return Err(MessageDecryptionError::MalformedContent);
    }
    let key_enc_nonce = key_enc_nonce_from_wrap_key(
        crypto,
        ciphersuite,
        &archive.wrap_key,
        sender_data.leaf_index,
        sender_data.generation,
    )
    .map_err(LibraryError::unexpected_crypto_error)?;
    let key_enc_aad = if ciphertext
        .aad()
        .starts_with(crate::framing::private_message::YOURN_REPLAY_AAD_MAGIC)
    {
        ciphertext.key_enc_aad(sender_data.leaf_index)?
    } else {
        Vec::new()
    };
    let wrapped = AeadKey::from_secret(archive.wrap_key.clone(), ciphersuite)
        .aead_open(crypto, ciphertext.key_enc(), &key_enc_aad, &key_enc_nonce)
        .map_err(|_| MessageDecryptionError::AeadError)?;
    if wrapped.len() != ciphersuite.aead_key_length() + ciphersuite.aead_nonce_length() {
        return Err(MessageDecryptionError::MalformedContent);
    }
    let (key_bytes, nonce_bytes) = wrapped.split_at(ciphersuite.aead_key_length());
    let content_key = AeadKey::from_secret(Secret::from_slice(key_bytes), ciphersuite);
    let content_nonce = AeadNonce::from_secret(Secret::from_slice(nonce_bytes));
    let prepared_nonce = content_nonce.xor_with_reuse_guard(&sender_data.reuse_guard);
    let verifiable = ciphertext.to_verifiable_content_from_content_key(
        ciphersuite,
        crypto,
        content_key,
        prepared_nonce,
        sender_data,
        &archive.serialized_context,
    )?;

    let leaf_index = verifiable
        .sender()
        .as_member()
        .ok_or(MessageDecryptionError::MalformedContent)?;
    let member = archive
        .leaves
        .iter()
        .find(|member| member.index == leaf_index)
        .ok_or(MessageDecryptionError::InvalidSignature)?;
    let signature_key = OpenMlsSignaturePublicKey::from_signature_key(
        SignaturePublicKey::from(member.signature_key.clone()),
        ciphersuite.signature_algorithm(),
    );
    let authenticated = verifiable
        .verify(crypto, &signature_key)
        .map_err(|_| MessageDecryptionError::InvalidSignature)?;
    let plaintext = authenticated
        .into_application_bytes()
        .ok_or(MessageDecryptionError::MalformedContent)?;
    Ok((
        plaintext,
        member.credential.serialized_content().to_vec(),
        ciphertext.aad().to_vec(),
    ))
}

fn decode_epoch_archive(bytes: &[u8]) -> Result<EpochArchiveData, ExportSecretsStoreError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(EPOCH_ARCHIVE_MAGIC.len())? != EPOCH_ARCHIVE_MAGIC {
        return Err(ExportSecretsStoreError::Archive("bad magic".into()));
    }
    let ciphersuite = Ciphersuite::try_from(cursor.u16()?)
        .map_err(|_| ExportSecretsStoreError::Archive("unknown ciphersuite".into()))?;
    let group_id = cursor.bytes()?.to_vec();
    let epoch = cursor.u64()?;
    let producing_commit_id = cursor.bytes()?.to_vec();
    let wrap_key = Secret::from_slice(cursor.bytes()?);
    let sender_data_secret = SenderDataSecret::from_archive_bytes(cursor.bytes()?);
    let serialized_context = cursor.bytes()?.to_vec();
    let leaf_count = cursor.u32()? as usize;
    let mut leaves = Vec::with_capacity(leaf_count);
    let mut previous_index = None;
    for _ in 0..leaf_count {
        let index = cursor.u32()?;
        if previous_index.is_some_and(|previous| index <= previous) {
            return Err(ExportSecretsStoreError::Archive(
                "leaves are not strictly ordered".into(),
            ));
        }
        previous_index = Some(index);
        let signature_key = cursor.bytes()?.to_vec();
        let credential_bytes = cursor.bytes()?.to_vec();
        let credential: Credential = BasicCredential::new(credential_bytes).into();
        leaves.push(Member::new(
            LeafNodeIndex::new(index),
            Vec::new(),
            signature_key,
            credential,
        ));
    }
    if !cursor.is_empty() {
        return Err(ExportSecretsStoreError::Archive("trailing bytes".into()));
    }
    Ok(EpochArchiveData {
        ciphersuite,
        group_id,
        epoch,
        producing_commit_id,
        wrap_key,
        sender_data_secret,
        serialized_context,
        leaves,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExportSecretsStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| ExportSecretsStoreError::Archive("length overflow".into()))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| ExportSecretsStoreError::Archive("truncated archive".into()))?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ExportSecretsStoreError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, ExportSecretsStoreError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ExportSecretsStoreError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<&'a [u8], ExportSecretsStoreError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}
