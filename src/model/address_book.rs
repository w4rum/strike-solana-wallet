use crate::constants::{HASH_LEN, PUBKEY_BYTES};
use crate::model::wallet::Wallet;
use crate::utils::Slots;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{Pack, Sealed};
use solana_program::pubkey::Pubkey;
use std::convert::TryFrom;

pub type AddressBook = Slots<AddressBookEntry, { Wallet::MAX_ADDRESS_BOOK_ENTRIES }>;
pub type DAppBook = Slots<DAppBookEntry, { Wallet::MAX_DAPP_BOOK_ENTRIES }>;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Copy)]
pub struct AddressBookEntryNameHash([u8; HASH_LEN]);

impl AddressBookEntryNameHash {
    pub fn new(bytes: &[u8; HASH_LEN]) -> Self {
        Self(*bytes)
    }

    pub fn zero() -> Self {
        Self::new(&[0; HASH_LEN])
    }

    pub fn to_bytes(&self) -> &[u8; HASH_LEN] {
        <&[u8; HASH_LEN]>::try_from(&self.0[..]).unwrap()
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Ord, PartialOrd)]
pub struct AddressBookEntry {
    pub address: Pubkey,
    pub name_hash: AddressBookEntryNameHash,
}

impl Sealed for AddressBookEntry {}

impl Pack for AddressBookEntry {
    const LEN: usize = 64;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, AddressBookEntry::LEN];
        let (address_dst, name_hash_dst) = mut_array_refs![dst, PUBKEY_BYTES, HASH_LEN];

        address_dst.copy_from_slice(self.address.as_ref());
        name_hash_dst.copy_from_slice(self.name_hash.to_bytes());
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, AddressBookEntry::LEN];
        let (address_bytes, name_hash_bytes) = array_refs![src, PUBKEY_BYTES, HASH_LEN];

        Ok(AddressBookEntry {
            address: Pubkey::new_from_array(*address_bytes),
            name_hash: AddressBookEntryNameHash::new(name_hash_bytes),
        })
    }
}

pub type DAppBookEntry = AddressBookEntry;
pub type DAppBookEntryNameHash = AddressBookEntryNameHash;
