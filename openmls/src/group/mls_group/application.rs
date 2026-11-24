use openmls_traits::signatures::Signer;

use crate::{
    ciphersuite::AeadKey,
    framing::{
        history::{encode_history_blob, key_enc_aad},
        private_message::PreparedContentKey,
    },
    storage::OpenMlsProvider,
    tree::secret_tree::SecretType,
};

use super::{errors::CreateMessageError, *};

impl MlsGroup {
    // === Application messages ===

    /// Creates an application message carrying the versioned history blob in
    /// MLS authenticated data.
    ///
    /// The MLS content key is derived from the secret tree *before* signing,
    /// because the wrapped key is part of the signed authenticated data. The
    /// blob itself is the only proprietary wire extension; `PrivateMessage`
    /// remains standard MLS.
    pub fn create_message_with_history<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
        replay_id: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError> {
        if !self.is_active() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        if !self.proposal_store().is_empty() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::PendingProposal,
            ));
        }
        if replay_id.is_empty() {
            return Err(LibraryError::custom("History replay identity is empty").into());
        }

        let sender_index = self.own_leaf_index();
        let ciphersuite = self.ciphersuite();
        let (generation, content_key, content_nonce, key_enc_nonce) = {
            let secrets = self.message_secrets_store.message_secrets_mut();
            let (generation, (content_key, content_nonce)) = secrets
                .secret_tree_mut()
                .secret_for_encryption(
                    ciphersuite,
                    provider.crypto(),
                    sender_index,
                    SecretType::ApplicationSecret,
                )
                .map_err(|_| LibraryError::custom("Failed to derive MLS content key"))?;
            let key_enc_nonce = secrets
                .key_enc_nonce(provider.crypto(), ciphersuite, sender_index, generation)
                .map_err(LibraryError::unexpected_crypto_error)?;
            (generation, content_key, content_nonce, key_enc_nonce)
        };

        let key_enc_aad = key_enc_aad(
            self.group_id(),
            self.epoch(),
            sender_index,
            generation,
            replay_id,
        )?;
        let wrap_key = self.message_secrets_store.message_secrets().wrap_key();
        let key_enc = AeadKey::from_secret(wrap_key.clone(), ciphersuite)
            .aead_seal(
                provider.crypto(),
                &[content_key.as_slice(), content_nonce.as_slice()].concat(),
                &key_enc_aad,
                &key_enc_nonce,
            )
            .map_err(LibraryError::unexpected_crypto_error)?;
        let history_blob = encode_history_blob(replay_id, &key_enc);

        let authenticated_content = AuthenticatedContent::new_application(
            sender_index,
            &history_blob,
            message,
            self.context(),
            signer,
        )?;
        let ciphertext = self
            .encrypt_with_content_key(
                authenticated_content,
                provider,
                PreparedContentKey {
                    generation,
                    content_key,
                    content_nonce,
                },
            )
            .map_err(|_| LibraryError::custom("Malformed history application content"))?;

        Ok(MlsMessageOut::from_private_message(
            ciphertext,
            self.version(),
        ))
    }

    /// Creates an application message.
    /// Returns `CreateMessageError::MlsGroupStateError::UseAfterEviction`
    /// if the member is no longer part of the group.
    /// Returns `CreateMessageError::MlsGroupStateError::PendingProposal` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError> {
        if !self.is_active() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        if !self.proposal_store().is_empty() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::PendingProposal,
            ));
        }

        let authenticated_content = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            &self.aad,
            message,
            self.context(),
            signer,
        )?;
        let ciphertext = self
            .encrypt(authenticated_content, provider)
            // We know the application message is wellformed and we have the key material of the current epoch
            .map_err(|_| LibraryError::custom("Malformed plaintext"))?;

        self.reset_aad();
        Ok(MlsMessageOut::from_private_message(
            ciphertext,
            self.version(),
        ))
    }
}
