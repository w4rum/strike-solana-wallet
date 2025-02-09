use crate::constants::HASH_LEN;
use crate::model::address_book::{AddressBook, AddressBookEntry};
use crate::model::multisig_op::BooleanSetting;
use crate::model::wallet::{Approvers, WalletGuidHash};
use crate::utils::SlotFlags;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{IsInitialized, Pack, Sealed};
use solana_program::pubkey::Pubkey;
use std::convert::TryFrom;
use std::time::Duration;

pub type AllowedDestinations = SlotFlags<AddressBookEntry, { AddressBook::FLAGS_STORAGE_SIZE }>;

const WHITELIST_SETTING_BIT: u8 = 0;
const DAPPS_SETTING_BIT: u8 = 1;

#[derive(Debug, Clone, Eq, PartialEq, Copy, Ord, PartialOrd, Default)]
pub struct BalanceAccountGuidHash([u8; HASH_LEN]);

impl BalanceAccountGuidHash {
    pub fn new(bytes: &[u8; HASH_LEN]) -> Self {
        Self(*bytes)
    }

    pub fn zero() -> Self {
        Self::new(&[0; HASH_LEN])
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Sealed for BalanceAccountGuidHash {}

impl Pack for BalanceAccountGuidHash {
    const LEN: usize = HASH_LEN;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self.to_bytes())
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        if src.len() == HASH_LEN {
            Ok(BalanceAccountGuidHash::new(array_ref![src, 0, HASH_LEN]))
        } else {
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

impl IsInitialized for BalanceAccountGuidHash {
    fn is_initialized(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Copy, Ord, PartialOrd)]
pub struct BalanceAccountNameHash([u8; HASH_LEN]);

impl BalanceAccountNameHash {
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

impl Sealed for BalanceAccountNameHash {}

impl Pack for BalanceAccountNameHash {
    const LEN: usize = HASH_LEN;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        dst.copy_from_slice(self.to_bytes())
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        if src.len() == HASH_LEN {
            Ok(BalanceAccountNameHash::new(array_ref![src, 0, HASH_LEN]))
        } else {
            Err(ProgramError::InvalidInstructionData)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd)]
pub struct BalanceAccount {
    pub guid_hash: BalanceAccountGuidHash,
    pub name_hash: BalanceAccountNameHash,
    pub approvals_required_for_transfer: u8,
    pub approval_timeout_for_transfer: Duration,
    pub transfer_approvers: Approvers,
    pub allowed_destinations: AllowedDestinations,
    pub whitelist_enabled: BooleanSetting,
    pub dapps_enabled: BooleanSetting,
}

impl Sealed for BalanceAccount {}

impl Pack for BalanceAccount {
    const LEN: usize = HASH_LEN +
        HASH_LEN +
        1 + // approvals_required_for_transfer
        8 + // approval_timeout_for_transfer
        Approvers::STORAGE_SIZE + // transfer approvers
        AllowedDestinations::STORAGE_SIZE +  // allowed destinations
        1; // boolean settings

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, BalanceAccount::LEN];
        let (
            guid_hash_dst,
            name_hash_dst,
            approvals_required_for_transfer_dst,
            approval_timeout_for_transfer_dst,
            approvers_dst,
            allowed_destinations_dst,
            boolean_settings_dst,
        ) = mut_array_refs![
            dst,
            HASH_LEN,
            HASH_LEN,
            1,
            8,
            Approvers::STORAGE_SIZE,
            AllowedDestinations::STORAGE_SIZE,
            1
        ];

        guid_hash_dst.copy_from_slice(&self.guid_hash.0);
        name_hash_dst.copy_from_slice(&self.name_hash.0);

        approvals_required_for_transfer_dst[0] = self.approvals_required_for_transfer;
        *approval_timeout_for_transfer_dst =
            self.approval_timeout_for_transfer.as_secs().to_le_bytes();

        approvers_dst.copy_from_slice(self.transfer_approvers.as_bytes());
        allowed_destinations_dst.copy_from_slice(self.allowed_destinations.as_bytes());
        boolean_settings_dst[0] |= self.whitelist_enabled.to_u8() << WHITELIST_SETTING_BIT;
        boolean_settings_dst[0] |= self.dapps_enabled.to_u8() << DAPPS_SETTING_BIT;
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, BalanceAccount::LEN];
        let (
            guid_hash_src,
            name_hash_src,
            approvals_required_for_transfer_src,
            approval_timeout_for_transfer_src,
            approvers_src,
            allowed_destinations_src,
            boolean_settings_src,
        ) = array_refs![
            src,
            HASH_LEN,
            HASH_LEN,
            1,
            8,
            Approvers::STORAGE_SIZE,
            AllowedDestinations::STORAGE_SIZE,
            1
        ];

        Ok(BalanceAccount {
            guid_hash: BalanceAccountGuidHash(*guid_hash_src),
            name_hash: BalanceAccountNameHash(*name_hash_src),
            approvals_required_for_transfer: approvals_required_for_transfer_src[0],
            approval_timeout_for_transfer: Duration::from_secs(u64::from_le_bytes(
                *approval_timeout_for_transfer_src,
            )),
            transfer_approvers: Approvers::new(*approvers_src),
            allowed_destinations: AllowedDestinations::new(*allowed_destinations_src),
            whitelist_enabled: BooleanSetting::from_u8(
                boolean_settings_src[0] & (1 << WHITELIST_SETTING_BIT),
            ),
            dapps_enabled: BooleanSetting::from_u8(
                boolean_settings_src[0] & (1 << DAPPS_SETTING_BIT),
            ),
        })
    }
}

impl BalanceAccount {
    pub fn is_whitelist_disabled(&self) -> bool {
        return self.whitelist_enabled == BooleanSetting::Off;
    }

    pub fn are_dapps_disabled(&self) -> bool {
        return self.dapps_enabled == BooleanSetting::Off;
    }

    pub fn has_whitelisted_destinations(&self) -> bool {
        return self.allowed_destinations.count_enabled() > 0;
    }

    /// Derive the PDA and "bump seed" of a BalanceAccount, given its GUID hash and the wallet guid hash.
    pub fn find_address(
        wallet_guid_hash: &WalletGuidHash,
        guid_hash: &BalanceAccountGuidHash,
        program_id: &Pubkey,
    ) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[wallet_guid_hash.to_bytes(), guid_hash.to_bytes()],
            program_id,
        )
    }
}
