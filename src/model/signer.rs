use solana_program::program_error::ProgramError;
use solana_program::pubkey::{Pubkey, PUBKEY_BYTES};
use solana_program::program_pack::{Sealed, Pack};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Ord, PartialOrd)]
pub struct Signer {
    pub key: Pubkey
}

impl Sealed for Signer {}

impl Pack for Signer {
    const LEN: usize = PUBKEY_BYTES;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self.key.as_ref());
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        Ok(Signer {
            key: Pubkey::new(src)
        })
    }
}
