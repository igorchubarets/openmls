//! This module defines the [`MessageSecrets`] struct that can be used for message decryption & verification

use super::*;
use openmls_traits::types::CryptoError;

/// Combined message secrets that need to be stored for later decryption/verification
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecrets {
    sender_data_secret: SenderDataSecret,
    membership_key: MembershipKey,
    confirmation_key: ConfirmationKey,
    serialized_context: Vec<u8>,
    secret_tree: SecretTree,
    /// Per-epoch wrap key, derived from the exporter secret (identical for
    /// every member). Used to wrap the per-message `keyEnc`. Rides into the
    /// exported epoch-secret blob; `#[serde(default)]` keeps legacy blobs
    /// deserializable.
    #[serde(default)]
    wrap_key: Secret,
}

#[cfg(not(feature = "crypto-debug"))]
impl core::fmt::Debug for MessageSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSecrets")
            .field("sender_data_secret", &"***")
            .field("membership_key", &"***")
            .field("confirmation_key", &"***")
            .field("serialized_context", &"***")
            .field("secret_tree", &"***")
            .field("wrap_key", &"***")
            .finish()
    }
}

// Public functions
impl MessageSecrets {
    ///Create new `MessageSecrets`
    pub(crate) fn new(
        sender_data_secret: SenderDataSecret,
        membership_key: MembershipKey,
        confirmation_key: ConfirmationKey,
        serialized_context: Vec<u8>,
        secret_tree: SecretTree,
        wrap_key: Secret,
    ) -> Self {
        Self {
            sender_data_secret,
            membership_key,
            confirmation_key,
            serialized_context,
            secret_tree,
            wrap_key,
        }
    }

    /// Get a reference to the message secrets's sender data secret.
    pub(crate) fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    /// Get a reference to the message secrets's membership key.
    pub(crate) fn membership_key(&self) -> &MembershipKey {
        &self.membership_key
    }

    /// Get a reference to the message secrets's confirmation key.
    pub(crate) fn confirmation_key(&self) -> &ConfirmationKey {
        &self.confirmation_key
    }

    /// Get a reference to the message secrets's serialized context.
    pub(crate) fn serialized_context(&self) -> &[u8] {
        self.serialized_context.as_ref()
    }

    /// Get a mutable reference to the message secrets's secret tree.
    pub(crate) fn secret_tree_mut(&mut self) -> &mut SecretTree {
        &mut self.secret_tree
    }

    /// Get a reference to the message secrets's wrap key.
    pub(crate) fn wrap_key(&self) -> &Secret {
        &self.wrap_key
    }

    /// Derive the deterministic per-message nonce used to wrap `keyEnc` under
    /// the epoch wrap key. A function of the wrap key, the sender leaf and the
    /// generation: unique per message within an epoch (each `(leaf, generation)`
    /// pair wraps a distinct ratchet key), identical for every member, and
    /// recomputable at unwrap time from the epoch-secret blob.
    pub(crate) fn key_enc_nonce(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        sender_leaf: LeafNodeIndex,
        generation: u32,
    ) -> Result<AeadNonce, CryptoError> {
        // The wrap key can be shorter than the HKDF PRK length, so first
        // extract a full-length PRK from it (HKDF-Extract accepts a salt of
        // any length; only the PRK is fixed-length).
        let context = [sender_leaf.u32().to_le_bytes(), generation.to_le_bytes()].concat();
        let prk = Secret::from_slice(b"yourn_keyenc").hkdf_extract(crypto, ciphersuite, &self.wrap_key)?;
        Ok(AeadNonce::from_secret(
            prk.kdf_expand_label(
                crypto,
                ciphersuite,
                "nonce",
                &context,
                ciphersuite.aead_nonce_length(),
            )?,
        ))
    }
}

// Test functions
impl MessageSecrets {
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn sender_data_secret_mut(&mut self) -> &mut SenderDataSecret {
        &mut self.sender_data_secret
    }

    #[cfg(test)]
    /// Update the message secrets's serialized context.
    pub(crate) fn set_serialized_context(&mut self, serialized_context: Vec<u8>) {
        self.serialized_context = serialized_context;
    }

    #[cfg(test)]
    /// Update the membership key.
    pub(crate) fn set_membership_key(&mut self, membership_key: Secret) {
        self.membership_key = MembershipKey::from_secret(membership_key);
    }

    #[cfg(test)]
    pub(crate) fn random(
        ciphersuite: Ciphersuite,
        rng: &impl OpenMlsRand,
        own_index: LeafNodeIndex,
    ) -> Self {
        Self {
            sender_data_secret: SenderDataSecret::random(ciphersuite, rng),
            membership_key: MembershipKey::random(ciphersuite, rng),
            confirmation_key: ConfirmationKey::random(ciphersuite, rng),
            serialized_context: rng.random_vec(10).expect("Not enough randomness."),
            secret_tree: SecretTree::new(
                EncryptionSecret::random(ciphersuite, rng),
                TreeSize::new(10),
                own_index,
            ),
            wrap_key: Secret::from_slice(
                &rng
                    .random_vec(ciphersuite.aead_key_length())
                    .expect("Not enough randomness."),
            ),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn replace_secret_tree(&mut self, secret_tree: SecretTree) -> SecretTree {
        std::mem::replace(&mut self.secret_tree, secret_tree)
    }
}

// In tests we allow comparing secrets.
#[cfg(any(test, feature = "test-utils"))]
impl PartialEq for MessageSecrets {
    fn eq(&self, other: &Self) -> bool {
        self.sender_data_secret == other.sender_data_secret
            && self.membership_key == other.membership_key
            && self.confirmation_key == other.confirmation_key
            && self.secret_tree == other.secret_tree
            && self.wrap_key == other.wrap_key
    }
}
