use std::borrow::BorrowMut;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use solana_program::account_info::AccountInfo;
use solana_program::program_pack::{Sealed, IsInitialized, Pack};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::{Pubkey, PUBKEY_BYTES};
use crate::instruction::{ProgramConfigUpdate, WalletConfigUpdate};
use solana_program::entrypoint::ProgramResult;
use solana_program::msg;
use crate::error::WalletError;
use crate::model::wallet_config::{AddressBookEntry, AllowedDestinations, WalletConfig};
use bitvec::prelude::*;
use crate::model::opt_array::OptArray;

pub type ConfigChangeApprovers = BitArr!(for ProgramConfig::MAX_SIGNERS, in u8);

#[derive(Debug)]
pub struct ProgramConfig {
    pub is_initialized: bool,
    // pub signers: Vec<Pubkey>,
    pub assistant: Pubkey,
    pub address_book: OptArray<AddressBookEntry, { ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES }>,
    pub approvals_required_for_config: u8,
    pub config_approvers: Vec<Pubkey>,
    pub wallets: Vec<WalletConfig>
}

impl Sealed for ProgramConfig {}

impl IsInitialized for ProgramConfig {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

pub fn validate_initiator(initiator: &AccountInfo, assistant_key: &Pubkey, approvers: &Vec<Pubkey>) -> ProgramResult {
    if !initiator.is_signer {
        return Err(WalletError::InvalidSignature.into());
    }
    if initiator.key == assistant_key || approvers.contains(initiator.key) {
        Ok(())
    } else {
        msg!("Transactions can only be initiated by an authorized account");
        Err(ProgramError::InvalidArgument)
    }
}

impl ProgramConfig {
    pub const MAX_WALLETS: usize = 10;
    pub const MAX_SIGNERS: usize = 25;
    pub const MAX_ADDRESS_BOOK_ENTRIES: usize = 100;

    pub fn validate_initiator(&self, initiator: &AccountInfo, assistant_key: &Pubkey) -> ProgramResult {
        return validate_initiator(initiator, assistant_key, &self.config_approvers);
    }

    pub fn validate_update(&self, config_update: &ProgramConfigUpdate) -> ProgramResult {
        let approvers_after_update = len_after_update(
            &self.config_approvers,
            &config_update.add_approvers,
            &config_update.remove_approvers
        );

        if approvers_after_update > ProgramConfig::MAX_SIGNERS {
            msg!("Program config supports up to {} approvers", ProgramConfig::MAX_SIGNERS);
            return Err(ProgramError::InvalidArgument);
        }

        if usize::from(config_update.approvals_required_for_config) > approvers_after_update {
            msg!(
                "Approvals required for config update {} can't exceed configured approvers count {}",
                config_update.approvals_required_for_config,
                approvers_after_update
            );
            return Err(ProgramError::InvalidArgument);
        }

        let addr_book_entries_after_update = self.address_book.len_after_update(
            &config_update.add_address_book_entries,
            &config_update.remove_address_book_entries
        );

        if addr_book_entries_after_update > ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES {
            msg!("Program config supports up to {} address book entries", ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES);
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    pub fn update(&mut self, config_update: &ProgramConfigUpdate) -> ProgramResult {
        self.validate_update(config_update)?;
        self.approvals_required_for_config = config_update.approvals_required_for_config;

        if config_update.add_approvers.len() > 0 || config_update.remove_approvers.len() > 0 {
            for approver_to_remove in &config_update.remove_approvers {
                self.config_approvers.retain(|approver| approver != approver_to_remove);
            }
            for approver_to_add in &config_update.add_approvers {
                self.config_approvers.push(*approver_to_add);
            }
        }

        if config_update.add_address_book_entries.len() > 0 || config_update.remove_address_book_entries.len() > 0 {
            self.address_book.add_items(&config_update.add_address_book_entries);
            for removed_entry_idx in self.address_book.remove_items(&config_update.remove_address_book_entries) {
                for wallet_config in self.wallets.iter_mut() {
                    wallet_config.allowed_destinations.set(removed_entry_idx, false);
                }
            }
        }

        Ok(())
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

    pub fn destination_allowed(&self, wallet_config: &WalletConfig, address: &Pubkey, name_hash: &[u8; 32]) -> Result<bool, ProgramError> {
        Ok(match self.address_book.find_index(&AddressBookEntry { address: *address, name_hash: *name_hash }) {
            Some(entry_idx) => wallet_config.allowed_destinations[entry_idx],
            None => false
        })
    }

    pub fn add_wallet_config(&mut self, wallet_guid_hash: &[u8; 32], config_update: &WalletConfigUpdate) {
        let mut allowed_destinations = AllowedDestinations::ZERO;
        for i in self.address_book.find_indexes(&config_update.add_allowed_destinations) {
            allowed_destinations.set(i, true);
        }

        let wallet_config = WalletConfig {
            wallet_guid_hash: *wallet_guid_hash,
            wallet_name_hash: config_update.name_hash,
            approvals_required_for_transfer: config_update.approvals_required_for_transfer,
            approvers: config_update.add_approvers.clone(),
            allowed_destinations
        };
        self.wallets.push(wallet_config);
    }

    pub fn validate_wallet_config_update(&self, wallet_config: &WalletConfig, config_update: &WalletConfigUpdate) -> ProgramResult {
        let approvers_after_update = len_after_update(
            &wallet_config.approvers,
            &config_update.add_approvers,
            &config_update.remove_approvers
        );

        if approvers_after_update > ProgramConfig::MAX_SIGNERS {
            msg!("Wallet config supports up to {} approvers", ProgramConfig::MAX_SIGNERS);
            return Err(ProgramError::InvalidArgument);
        }

        if self.address_book.find_indexes(&config_update.add_allowed_destinations).len() < config_update.add_allowed_destinations.len() {
            msg!("Address book does not contain one of the given destinations");
            return Err(ProgramError::InvalidArgument);
        }

        if usize::from(config_update.approvals_required_for_transfer) > approvers_after_update {
            msg!(
                "Approvals required for transfer {} can't exceed configured approvers count {}",
                config_update.approvals_required_for_transfer,
                approvers_after_update
            );
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    pub fn update_wallet_config(&mut self, wallet_guid_hash: &[u8; 32], config_update: &WalletConfigUpdate) -> ProgramResult {
        let wallet_config_idx = self.get_wallet_config_index(wallet_guid_hash)?;
        self.validate_wallet_config_update(&self.wallets[wallet_config_idx], config_update)?;

        let mut wallet_config = self.wallets[wallet_config_idx].borrow_mut();
        wallet_config.wallet_name_hash = config_update.name_hash;
        wallet_config.approvals_required_for_transfer = config_update.approvals_required_for_transfer;

        if config_update.add_approvers.len() > 0 || config_update.remove_approvers.len() > 0 {
            for approver_to_remove in &config_update.remove_approvers {
                wallet_config.approvers.retain(|approver| approver != approver_to_remove);
            }
            for approver_to_add in &config_update.add_approvers {
                wallet_config.approvers.push(*approver_to_add);
            }
        }

        if config_update.add_allowed_destinations.len() > 0 || config_update.remove_allowed_destinations.len() > 0 {
            for i in self.address_book.find_indexes(&config_update.add_allowed_destinations) {
                wallet_config.allowed_destinations.set(i, true);
            }
            for i in self.address_book.find_indexes(&config_update.remove_allowed_destinations) {
                wallet_config.allowed_destinations.set(i, false);
            }
        }

        Ok(())
    }
}

impl Pack for ProgramConfig {
    const LEN: usize = 1 + // is_initialized
        1 + // approvals_required_for_config
        1 + PUBKEY_BYTES * ProgramConfig::MAX_SIGNERS + // config_approvers with size
        PUBKEY_BYTES + // assistant account pubkey
        AddressBookEntry::LEN * ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES + // address book
        1 + WalletConfig::LEN * ProgramConfig::MAX_WALLETS; // wallets with size

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, ProgramConfig::LEN];
        let (
            is_initialized_dst,
            approvals_required_for_config_dst,
            config_approvers_count_dst,
            config_approvers_dst,
            assistant_account_dst,
            address_book_dst,
            wallets_count_dst,
            wallets_dst
        ) = mut_array_refs![dst,
            1,
            1,
            1,
            PUBKEY_BYTES * ProgramConfig::MAX_SIGNERS,
            PUBKEY_BYTES,
            ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES * AddressBookEntry::LEN,
            1,
            WalletConfig::LEN * ProgramConfig::MAX_WALLETS
        ];

        let ProgramConfig {
            is_initialized,
            approvals_required_for_config,
            config_approvers,
            assistant,
            address_book,
            wallets
        } = self;

        is_initialized_dst[0] = *is_initialized as u8;
        approvals_required_for_config_dst[0] = *approvals_required_for_config;

        config_approvers_count_dst[0] = config_approvers.len() as u8;
        config_approvers_dst.fill(0);
        config_approvers_dst
            .chunks_exact_mut(PUBKEY_BYTES)
            .take(config_approvers.len())
            .enumerate()
            .for_each(|(i, chunk)| chunk.copy_from_slice(&config_approvers[i].to_bytes()));

        assistant_account_dst.copy_from_slice(&assistant.to_bytes());

        address_book.pack_into_slice(address_book_dst);

        wallets_count_dst[0] = wallets.len() as u8;
        wallets_dst.fill(0);
        wallets_dst
            .chunks_exact_mut(WalletConfig::LEN)
            .take(wallets.len())
            .enumerate()
            .for_each(|(i, chunk)| wallets[i].pack_into_slice(chunk));
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, ProgramConfig::LEN];
        let (
            is_initialized,
            approvals_required_for_config,
            configured_approvers_count,
            config_approvers_bytes,
            assistant,
            address_book_bytes,
            wallets_count,
            wallets_bytes
        ) = array_refs![src,
            1,
            1,
            1,
            PUBKEY_BYTES * ProgramConfig::MAX_SIGNERS,
            PUBKEY_BYTES,
            ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES * AddressBookEntry::LEN,
            1,
            WalletConfig::LEN * ProgramConfig::MAX_WALLETS
        ];

        let is_initialized = match is_initialized {
            [0] => false,
            [1] => true,
            _ => return Err(ProgramError::InvalidAccountData),
        };

        let mut config_approvers = Vec::with_capacity(ProgramConfig::MAX_SIGNERS);
        config_approvers_bytes
            .chunks_exact(PUBKEY_BYTES)
            .take(usize::from(configured_approvers_count[0]))
            .for_each(|chunk| {
                config_approvers.push(Pubkey::new(chunk));
            });

        let mut wallets = Vec::with_capacity(ProgramConfig::MAX_WALLETS);
        wallets_bytes
            .chunks_exact(WalletConfig::LEN)
            .take(usize::from(wallets_count[0]))
            .for_each(|chunk| {
                wallets.push(WalletConfig::unpack_from_slice(chunk).unwrap());
            });

        Ok(ProgramConfig {
            is_initialized,
            approvals_required_for_config: approvals_required_for_config[0],
            config_approvers,
            assistant: Pubkey::new_from_array(*assistant),
            address_book: OptArray::unpack_from_slice(address_book_bytes)?,
            wallets
        })
    }
}

fn len_after_update<A: PartialEq>(current_items: &Vec<A>, add_items: &Vec<A>, remove_items: &Vec<A>) -> usize {
    let mut result = 0;
    for item in current_items {
        if !remove_items.contains(&item) {
            result += 1;
        }
    }
    for item_to_add in add_items {
        if !current_items.contains(&item_to_add) {
            result += 1;
        }
    }
    result
}
