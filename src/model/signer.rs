use crate::constants::HASH_LEN;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{Pack, Sealed};
use solana_program::pubkey::{Pubkey, PUBKEY_BYTES};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Ord, PartialOrd)]
pub struct Signer {
    pub key: Pubkey,
}

impl Signer {
    pub fn new(key: Pubkey) -> Self {
        Signer { key }
    }
}

impl Sealed for Signer {}

impl Pack for Signer {
    const LEN: usize = PUBKEY_BYTES;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self.key.as_ref());
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, Signer::LEN];
        Ok(Signer {
            key: Pubkey::new_from_array(*src),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Ord, PartialOrd)]
pub struct NamedSigner {
    pub key: Pubkey,
    pub name_hash: [u8; HASH_LEN],
}

impl NamedSigner {
    pub fn new(key: Pubkey, name_hash: [u8; HASH_LEN]) -> Self {
        NamedSigner { key, name_hash }
    }
}

impl Sealed for NamedSigner {}

impl Pack for NamedSigner {
    const LEN: usize = PUBKEY_BYTES + HASH_LEN;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, PUBKEY_BYTES + HASH_LEN];
        let (key_dst, name_hash_dst) = mut_array_refs![dst, PUBKEY_BYTES, HASH_LEN];
        key_dst.copy_from_slice(self.key.as_ref());
        name_hash_dst.copy_from_slice(self.name_hash.as_ref());
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, Signer::LEN + HASH_LEN];
        let (key, name_hash) = array_refs![src, Signer::LEN, HASH_LEN];
        Ok(NamedSigner {
            key: Pubkey::new_from_array(*key),
            name_hash: *name_hash,
        })
    }
}
