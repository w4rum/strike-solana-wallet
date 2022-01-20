use std::borrow::BorrowMut;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_program::account_info::AccountInfo;
use solana_program::program_pack::{Sealed, IsInitialized, Pack};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use crate::instruction::{ProgramConfigUpdate, WalletConfigUpdate};
use solana_program::entrypoint::ProgramResult;
use solana_program::msg;
use crate::error::WalletError;
use crate::model::wallet_config::{AddressBookEntry, WalletConfig};
use itertools::Itertools;
use crate::model::opt_array::OptArray;
use crate::model::signer::Signer;
use bitvec::prelude::*;

pub type Signers = OptArray<Signer, { ProgramConfig::MAX_SIGNERS }>;
pub type AddressBook = OptArray<AddressBookEntry, { ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES }>;
pub type AllowedDestinations = BitArr!(for ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES, in u8);
pub type Approvers = BitArr!(for ProgramConfig::MAX_SIGNERS, in u8);

#[derive(Debug, Clone)]
pub struct ProgramConfig {
    pub is_initialized: bool,
    pub signers: Signers,
    pub assistant: Signer,
    pub address_book: AddressBook,
    pub approvals_required_for_config: u8,
    pub config_approvers: Approvers,
    pub wallets: Vec<WalletConfig>
}

impl Sealed for ProgramConfig {}

impl IsInitialized for ProgramConfig {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl ProgramConfig {
    pub const MAX_WALLETS: usize = 10;
    pub const MAX_SIGNERS: usize = 25;
    pub const MAX_ADDRESS_BOOK_ENTRIES: usize = 100;

    pub fn get_config_approvers_keys(&self) -> Vec<Pubkey> {
        self.get_approvers_keys(&self.config_approvers)
    }

    pub fn get_transfer_approvers_keys(&self, wallet_config: &WalletConfig) -> Vec<Pubkey> {
        self.get_approvers_keys(&wallet_config.transfer_approvers)
    }

    fn get_approvers_keys(&self, approvers: &Approvers) -> Vec<Pubkey> {
        approvers
            .iter_ones()
            .filter_map(|idx| self.signers[idx].map(|it| it.key))
            .collect_vec()
    }

    fn get_wallet_config_index(&self, wallet_guid_hash: &[u8; 32]) -> Result<usize, ProgramError> {
        self.wallets
            .iter()
            .position(|it| it.wallet_guid_hash == *wallet_guid_hash)
            .ok_or(WalletError::WalletNotFound.into())
    }

    pub fn get_wallet_config(&self, wallet_guid_hash: &[u8; 32]) -> Result<&WalletConfig, ProgramError> {
        Ok(&self.wallets[self.get_wallet_config_index(wallet_guid_hash)?])
    }

    pub fn validate_config_initiator(&self, initiator: &AccountInfo) -> ProgramResult {
        return self.validate_initiator(initiator, &self.get_config_approvers_keys());
    }

    pub fn validate_transfer_initiator(&self, wallet_config: &WalletConfig, initiator: &AccountInfo) -> ProgramResult {
        return self.validate_initiator(initiator, &self.get_transfer_approvers_keys(wallet_config));
    }

    fn validate_initiator(&self, initiator: &AccountInfo, approvers: &Vec<Pubkey>) -> ProgramResult {
        if !initiator.is_signer {
            return Err(WalletError::InvalidSignature.into());
        }
        if initiator.key == &self.assistant.key || approvers.contains(initiator.key) {
            Ok(())
        } else {
            msg!("Transactions can only be initiated by an authorized account");
            Err(ProgramError::InvalidArgument)
        }
    }

    pub fn destination_allowed(&self, wallet_config: &WalletConfig, address: &Pubkey, name_hash: &[u8; 32]) -> Result<bool, ProgramError> {
        Ok(match self.address_book.find_index(&AddressBookEntry { address: *address, name_hash: *name_hash }) {
            Some(entry_idx) => wallet_config.allowed_destinations[entry_idx],
            None => false
        })
    }

    pub fn validate_update(&self, config_update: &ProgramConfigUpdate) -> ProgramResult {
        let mut self_clone = self.clone();
        self_clone.update(config_update)
    }

    pub fn update(&mut self, config_update: &ProgramConfigUpdate) -> ProgramResult {
        self.approvals_required_for_config = config_update.approvals_required_for_config;

        if config_update.add_signers.len() > 0 || config_update.remove_signers.len() > 0 {
            self.remove_signers(&config_update.remove_signers);
            self.add_signers(&config_update.add_signers)?;
        }

        if config_update.add_config_approvers.len() > 0 || config_update.remove_config_approvers.len() > 0 {
            self.disable_config_approvers(&config_update.remove_config_approvers);
            self.enable_config_approvers(&config_update.add_config_approvers)?;
        }

        if config_update.add_address_book_entries.len() > 0 || config_update.remove_address_book_entries.len() > 0 {
            self.remove_address_book_entries(&config_update.remove_address_book_entries);
            self.add_address_book_entries(&config_update.add_address_book_entries)?;
        }

        let approvers_count_after_update = self.config_approvers.count_ones();
        if usize::from(config_update.approvals_required_for_config) > approvers_count_after_update {
            msg!(
                "Approvals required for config {} can't exceed configured approvers count {}",
                config_update.approvals_required_for_config,
                approvers_count_after_update
            );
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    pub fn validate_add_wallet_config(&self, wallet_guid_hash: &[u8; 32], config_update: &WalletConfigUpdate) -> ProgramResult {
        let mut self_clone = self.clone();
        self_clone.add_wallet_config(wallet_guid_hash, config_update)
    }

    pub fn add_wallet_config(&mut self, wallet_guid_hash: &[u8; 32], config_update: &WalletConfigUpdate) -> ProgramResult {
        let wallet_config = WalletConfig {
            wallet_guid_hash: *wallet_guid_hash,
            wallet_name_hash: [0; 32],
            approvals_required_for_transfer: 0,
            transfer_approvers: Approvers::ZERO,
            allowed_destinations: AllowedDestinations::ZERO
        };
        self.wallets.push(wallet_config);
        self.update_wallet_config(wallet_guid_hash, config_update)
    }

    pub fn validate_wallet_config_update(&self, wallet_guid_hash: &[u8; 32], config_update: &WalletConfigUpdate) -> ProgramResult {
        let mut self_clone = self.clone();
        self_clone.update_wallet_config(wallet_guid_hash, config_update)
    }

    pub fn update_wallet_config(&mut self, wallet_guid_hash: &[u8; 32], config_update: &WalletConfigUpdate) -> ProgramResult {
        let wallet_config_idx = self.get_wallet_config_index(wallet_guid_hash)?;

        if config_update.add_transfer_approvers.len() > 0 || config_update.remove_transfer_approvers.len() > 0 {
            self.disable_transfer_approvers(wallet_config_idx, &config_update.remove_transfer_approvers);
            self.enable_transfer_approvers(wallet_config_idx, &config_update.add_transfer_approvers)?;
        }

        if config_update.add_allowed_destinations.len() > 0 || config_update.remove_allowed_destinations.len() > 0 {
            self.disable_transfer_destinations(wallet_config_idx, &config_update.remove_allowed_destinations);
            self.enable_transfer_destinations(wallet_config_idx, &config_update.add_allowed_destinations)?;
        }

        let wallet_config = &mut self.wallets[wallet_config_idx].borrow_mut();
        wallet_config.wallet_name_hash = config_update.name_hash;
        wallet_config.approvals_required_for_transfer = config_update.approvals_required_for_transfer;

        let approvers_count_after_update = wallet_config.transfer_approvers.count_ones();
        if usize::from(config_update.approvals_required_for_transfer) > approvers_count_after_update {
            msg!(
                "Approvals required for transfer {} can't exceed configured approvers count {}",
                config_update.approvals_required_for_transfer,
                approvers_count_after_update
            );
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    fn enable_config_approvers(&mut self, approvers: &Vec<Signer>) -> ProgramResult {
        let signer_indexes = self.signers.find_indexes(approvers);
        if signer_indexes.len() < approvers.len() {
            msg!("One of the given config approvers is not configured as signer");
            return Err(ProgramError::InvalidArgument);
        }
        for signer_idx in signer_indexes {
            self.config_approvers.set(signer_idx, true);
        }
        Ok(())
    }

    fn disable_config_approvers(&mut self, approvers: &Vec<Signer>) {
        for signer_idx in self.signers.find_indexes(approvers) {
            self.config_approvers.set(signer_idx, false);
        }
    }

    fn add_signers(&mut self, signers_to_add: &Vec<Signer>) -> ProgramResult {
        if !self.signers.add_items(signers_to_add) {
            msg!("Program config supports up to {} signers", ProgramConfig::MAX_SIGNERS);
            return Err(ProgramError::InvalidArgument);
        }
        Ok(())
    }

    fn remove_signers(&mut self, signers_to_remove: &Vec<Signer>) {
        for removed_signer_idx in self.signers.remove_items(signers_to_remove) {
            self.config_approvers.set(removed_signer_idx, false);
            for wallet_config in self.wallets.iter_mut() {
                wallet_config.transfer_approvers.set(removed_signer_idx, false);
            }
        }
    }

    fn add_address_book_entries(&mut self, entries_to_add: &Vec<AddressBookEntry>) -> ProgramResult {
        if !self.address_book.add_items(entries_to_add) {
            msg!("Program config supports up to {} address book entries", ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES);
            return Err(ProgramError::InvalidArgument);
        }
        Ok(())
    }

    fn remove_address_book_entries(&mut self, entries_to_remove: &Vec<AddressBookEntry>) {
        for removed_entry_idx in self.address_book.remove_items(entries_to_remove) {
            for wallet_config in self.wallets.iter_mut() {
                wallet_config.allowed_destinations.set(removed_entry_idx, false);
            }
        }
    }

    fn enable_transfer_approvers(&mut self, wallet_config_index: usize, approvers: &Vec<Signer>) -> ProgramResult {
        let signer_indexes = self.signers.find_indexes(approvers);
        if signer_indexes.len() < approvers.len() {
            msg!("One of the given transfer approvers is not configured as signer");
            return Err(ProgramError::InvalidArgument);
        }
        for i in signer_indexes {
            self.wallets[wallet_config_index].transfer_approvers.set(i, true);
        }
        Ok(())
    }

    fn disable_transfer_approvers(&mut self, wallet_config_index: usize, approvers: &Vec<Signer>) {
        for i in self.signers.find_indexes(approvers) {
            self.wallets[wallet_config_index].transfer_approvers.set(i, false);
        }
    }

    fn enable_transfer_destinations(&mut self, wallet_config_index: usize, destinations: &Vec<AddressBookEntry>) -> ProgramResult {
        let dst_indexes = self.address_book.find_indexes(destinations);
        if dst_indexes.len() < destinations.len() {
            msg!("Address book does not contain one of the given destinations");
            return Err(ProgramError::InvalidArgument);
        }
        for i in dst_indexes {
            self.wallets[wallet_config_index].allowed_destinations.set(i, true);
        }
        Ok(())
    }

    fn disable_transfer_destinations(&mut self, wallet_config_index: usize, destinations: &Vec<AddressBookEntry>) {
        for i in self.address_book.find_indexes(destinations) {
            self.wallets[wallet_config_index].allowed_destinations.set(i, false);
        }
    }
}

impl Pack for ProgramConfig {
    const LEN: usize = 1 + // is_initialized
        Signers::LEN +
        Signer::LEN + // assistant
        AddressBook::LEN +
        1 + // approvals_required_for_config
        4 + // config approvers bitvec
        1 + WalletConfig::LEN * ProgramConfig::MAX_WALLETS; // wallets with size

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, ProgramConfig::LEN];
        let (
            is_initialized_dst,
            signers_dst,
            assistant_account_dst,
            address_book_dst,
            approvals_required_for_config_dst,
            config_approvers_dst,
            wallets_count_dst,
            wallets_dst
        ) = mut_array_refs![dst,
            1,
            Signers::LEN,
            Signer::LEN,
            AddressBook::LEN,
            1,
            4,
            1,
            WalletConfig::LEN * ProgramConfig::MAX_WALLETS
        ];

        is_initialized_dst[0] = self.is_initialized as u8;

        self.signers.pack_into_slice(signers_dst);
        self.assistant.pack_into_slice(assistant_account_dst);
        self.address_book.pack_into_slice(address_book_dst);

        approvals_required_for_config_dst[0] = self.approvals_required_for_config;

        config_approvers_dst.copy_from_slice(self.config_approvers.as_raw_slice());

        wallets_count_dst[0] = self.wallets.len() as u8;
        wallets_dst.fill(0);
        wallets_dst
            .chunks_exact_mut(WalletConfig::LEN)
            .take(self.wallets.len())
            .enumerate()
            .for_each(|(i, chunk)| self.wallets[i].pack_into_slice(chunk));
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, ProgramConfig::LEN];
        let (
            is_initialized,
            signers_src,
            assistant,
            address_book_src,
            approvals_required_for_config,
            config_approvers_src,
            wallets_count,
            wallets_src
        ) = array_refs![src,
            1,
            Signers::LEN,
            Signer::LEN,
            AddressBook::LEN,
            1,
            4,
            1,
            WalletConfig::LEN * ProgramConfig::MAX_WALLETS
        ];

        let is_initialized = match is_initialized {
            [0] => false,
            [1] => true,
            _ => return Err(ProgramError::InvalidAccountData),
        };

        let mut wallets = Vec::with_capacity(ProgramConfig::MAX_WALLETS);
        wallets_src
            .chunks_exact(WalletConfig::LEN)
            .take(usize::from(wallets_count[0]))
            .for_each(|chunk| {
                wallets.push(WalletConfig::unpack_from_slice(chunk).unwrap());
            });

        Ok(ProgramConfig {
            is_initialized,
            signers: Signers::unpack_from_slice(signers_src)?,
            assistant: Signer::unpack_from_slice(assistant)?,
            address_book: AddressBook::unpack_from_slice(address_book_src)?,
            approvals_required_for_config: approvals_required_for_config[0],
            config_approvers: Approvers::new(*config_approvers_src),
            wallets
        })
    }
}
