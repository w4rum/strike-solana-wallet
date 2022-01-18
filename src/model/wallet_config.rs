use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_program::account_info::AccountInfo;
use solana_program::program_pack::{Sealed, Pack};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::{Pubkey, PUBKEY_BYTES};
use solana_program::entrypoint::ProgramResult;
use crate::model::program_config::{ProgramConfig, validate_initiator};
use bitvec::prelude::*;

pub type AllowedDestinations = BitArr!(for ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES, in u8);

#[derive(Debug)]
pub struct WalletConfig {
    pub wallet_guid_hash: [u8; 32],
    pub wallet_name_hash: [u8; 32],
    pub approvals_required_for_transfer: u8,
    pub approvers: Vec<Pubkey>,
    pub allowed_destinations: AllowedDestinations
}

impl WalletConfig {
    pub fn validate_initiator(&self, initiator: &AccountInfo, assistant_key: &Pubkey) -> ProgramResult {
        return validate_initiator(initiator, assistant_key, &self.approvers);
    }
}

impl Sealed for WalletConfig {}

impl Pack for WalletConfig {
    const LEN: usize = 32 + // guid_hash
        32 + // name_hash
        1 + // approvals_required_for_transfer
        1 + PUBKEY_BYTES * ProgramConfig::MAX_SIGNERS + // approvers with size
        13; // size of allowed destinations bitvec

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, WalletConfig::LEN];
        let (
            guid_hash_dst,
            name_hash_dst,
            approvals_required_for_transfer_dst,
            configured_approvers_count_dst,
            approvers_dst,
            allowed_destinations_dst
        ) = mut_array_refs![dst, 32, 32, 1, 1, PUBKEY_BYTES * ProgramConfig::MAX_SIGNERS, 13];

        guid_hash_dst.copy_from_slice(&self.wallet_guid_hash);
        name_hash_dst.copy_from_slice(&self.wallet_name_hash);

        approvals_required_for_transfer_dst[0] = self.approvals_required_for_transfer;

        configured_approvers_count_dst[0] = self.approvers.len() as u8;
        approvers_dst.fill(0);
        approvers_dst
            .chunks_exact_mut(PUBKEY_BYTES)
            .take(self.approvers.len())
            .enumerate()
            .for_each(|(i, chunk)| chunk.copy_from_slice(&self.approvers[i].to_bytes()));

        allowed_destinations_dst.copy_from_slice(self.allowed_destinations.as_raw_slice());
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, WalletConfig::LEN];
        let (
            guid_hash,
            name_hash,
            approvals_required_for_transfer,
            configured_approvers_count,
            approvers_bytes,
            allowed_destinations_bytes
        ) = array_refs![src, 32, 32, 1, 1, PUBKEY_BYTES * ProgramConfig::MAX_SIGNERS, 13];

        let configured_approvers_count = usize::from(configured_approvers_count[0]);
        let mut approvers = Vec::with_capacity(ProgramConfig::MAX_SIGNERS);
        approvers_bytes
            .chunks_exact(PUBKEY_BYTES)
            .take(configured_approvers_count)
            .for_each(|chunk| {
                let approver = Pubkey::new(chunk);
                approvers.push(approver);
            });

        Ok(WalletConfig {
            wallet_guid_hash: *guid_hash,
            wallet_name_hash: *name_hash,
            approvals_required_for_transfer: approvals_required_for_transfer[0],
            approvers,
            allowed_destinations: AllowedDestinations::new(*allowed_destinations_bytes)
        })
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct AddressBookEntry {
    pub address: Pubkey,
    pub name_hash: [u8; 32],
}

impl AddressBookEntry {
    pub const LEN: usize = 64;
    pub const NULL: AddressBookEntry = AddressBookEntry {
        address: Pubkey::new_from_array([0; 32]),
        name_hash: [0; 32]
    };

    pub fn make_null(&mut self) {
        self.address = Pubkey::new_from_array([0; 32]);
        self.name_hash = [0; 32];
    }

    pub fn copy_from(&mut self, other: &AddressBookEntry) {
        self.address = other.address;
        self.name_hash = other.name_hash;
    }

    pub fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, AddressBookEntry::LEN];
        let (
            address_dst,
            name_hash_dst
        ) = mut_array_refs![dst, 32, 32];

        address_dst.copy_from_slice(self.address.as_ref());
        name_hash_dst.copy_from_slice(&self.name_hash);
    }

    pub fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
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

