//! Versioned history envelope carried in MLS `authenticated_data`.
//!
//! The MLS `PrivateMessage` frame stays standard. The only proprietary data is
//! this application-level blob, which is signed by the MLS sender and carries
//! the per-message content key needed for own-message and archived decryption.

use tls_codec::{Serialize, TlsSerialize, TlsSize, VLByteSlice};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    error::LibraryError,
    framing::errors::MessageDecryptionError,
    group::{GroupEpoch, GroupId},
};

pub(crate) const HISTORY_BLOB_MAGIC: &[u8; 16] = b"YRN-HISTORY-AAD\0";
pub(crate) const HISTORY_BLOB_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HistoryBlob {
    pub(crate) replay_id: Vec<u8>,
    pub(crate) key_enc: Vec<u8>,
}

/// Encode the versioned history blob placed in MLS authenticated data.
pub(crate) fn encode_history_blob(replay_id: &[u8], key_enc: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(HISTORY_BLOB_MAGIC.len() + 9 + replay_id.len() + key_enc.len());
    out.extend_from_slice(HISTORY_BLOB_MAGIC);
    out.push(HISTORY_BLOB_VERSION);
    out.extend_from_slice(&(replay_id.len() as u32).to_le_bytes());
    out.extend_from_slice(replay_id);
    out.extend_from_slice(&(key_enc.len() as u32).to_le_bytes());
    out.extend_from_slice(key_enc);
    out
}

/// Parse and validate a history blob from MLS authenticated data.
pub(crate) fn decode_history_blob(aad: &[u8]) -> Result<HistoryBlob, MessageDecryptionError> {
    let magic_len = HISTORY_BLOB_MAGIC.len();
    if aad.len() < magic_len + 5 || &aad[..magic_len] != HISTORY_BLOB_MAGIC {
        return Err(MessageDecryptionError::MalformedContent);
    }
    if aad[magic_len] != HISTORY_BLOB_VERSION {
        return Err(MessageDecryptionError::MalformedContent);
    }

    let mut offset = magic_len + 1;
    let replay_len = read_u32(aad, &mut offset)?;
    let replay_id = read_bytes(aad, &mut offset, replay_len)?;
    let key_enc_len = read_u32(aad, &mut offset)?;
    let key_enc = read_bytes(aad, &mut offset, key_enc_len)?;
    if offset != aad.len() || replay_id.is_empty() || key_enc.is_empty() {
        return Err(MessageDecryptionError::MalformedContent);
    }

    Ok(HistoryBlob {
        replay_id: replay_id.to_vec(),
        key_enc: key_enc.to_vec(),
    })
}

fn read_u32(aad: &[u8], offset: &mut usize) -> Result<usize, MessageDecryptionError> {
    let end = offset
        .checked_add(4)
        .ok_or(MessageDecryptionError::MalformedContent)?;
    let bytes = aad
        .get(*offset..end)
        .ok_or(MessageDecryptionError::MalformedContent)?;
    *offset = end;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| MessageDecryptionError::MalformedContent)?,
    ) as usize)
}

fn read_bytes<'a>(
    aad: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], MessageDecryptionError> {
    let end = offset
        .checked_add(length)
        .ok_or(MessageDecryptionError::MalformedContent)?;
    let bytes = aad
        .get(*offset..end)
        .ok_or(MessageDecryptionError::MalformedContent)?;
    *offset = end;
    Ok(bytes)
}

/// AAD binding the wrapped MLS content key to the message that produced it.
/// The ciphertext itself is authenticated by the MLS framing signature.
#[derive(TlsSerialize, TlsSize)]
struct HistoryKeyEncAad<'a> {
    version: u8,
    group_id: GroupId,
    epoch: GroupEpoch,
    sender: u32,
    generation: u32,
    replay_id: VLByteSlice<'a>,
}

pub(crate) fn key_enc_aad(
    group_id: &GroupId,
    epoch: GroupEpoch,
    sender: LeafNodeIndex,
    generation: u32,
    replay_id: &[u8],
) -> Result<Vec<u8>, LibraryError> {
    HistoryKeyEncAad {
        version: HISTORY_BLOB_VERSION,
        group_id: group_id.clone(),
        epoch,
        sender: sender.u32(),
        generation,
        replay_id: VLByteSlice(replay_id),
    }
    .tls_serialize_detached()
    .map_err(LibraryError::missing_bound_check)
}
