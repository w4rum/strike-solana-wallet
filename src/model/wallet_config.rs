use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_program::program_pack::{Sealed, Pack};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use crate::model::program_config::ProgramConfig;
use bitvec::prelude::*;

pub type AllowedDestinations = BitArr!(for ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES, in u8);
pub type Approvers = BitArr!(for ProgramConfig::MAX_SIGNERS, in u8);

#[derive(Debug, Clone)]
pub struct WalletConfig {
    pub wallet_guid_hash: [u8; 32],
    pub wallet_name_hash: [u8; 32],
    pub approvals_required_for_transfer: u8,
    pub transfer_approvers: Approvers,
    pub allowed_destinations: AllowedDestinations
}

impl Sealed for WalletConfig {}

impl Pack for WalletConfig {
    const LEN: usize = 32 + // guid_hash
        32 + // name_hash
        1 + // approvals_required_for_transfer
        4 + // size of approvers bitvec
        13; // size of allowed destinations bitvec

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, WalletConfig::LEN];
        let (
            guid_hash_dst,
            name_hash_dst,
            approvals_required_for_transfer_dst,
            approvers_dst,
            allowed_destinations_dst
        ) = mut_array_refs![dst, 32, 32, 1, 4, 13];

        guid_hash_dst.copy_from_slice(&self.wallet_guid_hash);
        name_hash_dst.copy_from_slice(&self.wallet_name_hash);

        approvals_required_for_transfer_dst[0] = self.approvals_required_for_transfer;

        approvers_dst.copy_from_slice(self.transfer_approvers.as_raw_slice());
        allowed_destinations_dst.copy_from_slice(self.allowed_destinations.as_raw_slice());
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, WalletConfig::LEN];
        let (
            guid_hash_src,
            name_hash_src,
            approvals_required_for_transfer_src,
            approvers_src,
            allowed_destinations_src
        ) = array_refs![src, 32, 32, 1, 4, 13];

        Ok(WalletConfig {
            wallet_guid_hash: *guid_hash_src,
            wallet_name_hash: *name_hash_src,
            approvals_required_for_transfer: approvals_required_for_transfer_src[0],
            transfer_approvers: Approvers::new(*approvers_src),
            allowed_destinations: AllowedDestinations::new(*allowed_destinations_src)
        })
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct AddressBookEntry {
    pub address: Pubkey,
    pub name_hash: [u8; 32],
}

impl Sealed for AddressBookEntry {}

impl Pack for AddressBookEntry {
    const LEN: usize = 64;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, AddressBookEntry::LEN];
        let (
            address_dst,
            name_hash_dst
        ) = mut_array_refs![dst, 32, 32];

        address_dst.copy_from_slice(self.address.as_ref());
        name_hash_dst.copy_from_slice(&self.name_hash);
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, AddressBookEntry::LEN];
        let (
            address_bytes,
            name_hash_bytes
        ) = array_refs![src, 32, 32];

        Ok(AddressBookEntry {
            address: Pubkey::new_from_array(*address_bytes),
            name_hash: *name_hash_bytes
        })
    }
}

