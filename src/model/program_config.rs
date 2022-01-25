use crate::error::WalletError;
use crate::instruction::{ProgramConfigUpdate, WalletConfigUpdate};
use crate::model::signer::Signer;
use crate::model::wallet_config::{AddressBookEntry, WalletConfig};
use crate::utils::{GetSlotIds, SlotFlags, SlotId, Slots};
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use itertools::Itertools;
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::msg;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{IsInitialized, Pack, Sealed};
use solana_program::pubkey::Pubkey;
use std::borrow::BorrowMut;
use std::time::Duration;

pub type Signers = Slots<Signer, { ProgramConfig::MAX_SIGNERS }>;
pub type Approvers = SlotFlags<Signer, { Signers::FLAGS_STORAGE_SIZE }>;

pub type AddressBook = Slots<AddressBookEntry, { ProgramConfig::MAX_ADDRESS_BOOK_ENTRIES }>;
pub type AllowedDestinations = SlotFlags<AddressBookEntry, { AddressBook::FLAGS_STORAGE_SIZE }>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProgramConfig {
    pub is_initialized: bool,
    pub signers: Signers,
    pub assistant: Signer,
    pub address_book: AddressBook,
    pub approvals_required_for_config: u8,
    pub approval_timeout_for_config: Duration,
    pub config_approvers: Approvers,
    pub wallets: Vec<WalletConfig>,
}

impl Sealed for ProgramConfig {}

impl IsInitialized for ProgramConfig {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl ProgramConfig {
    pub const MAX_WALLETS: usize = 10;
    pub const MAX_SIGNERS: usize = 24;
    pub const MAX_ADDRESS_BOOK_ENTRIES: usize = 128;

    pub fn get_config_approvers_keys(&self) -> Vec<Pubkey> {
        self.get_approvers_keys(&self.config_approvers)
    }

    pub fn get_transfer_approvers_keys(&self, wallet_config: &WalletConfig) -> Vec<Pubkey> {
        self.get_approvers_keys(&wallet_config.transfer_approvers)
    }

    fn get_approvers_keys(&self, approvers: &Approvers) -> Vec<Pubkey> {
        approvers
            .iter_enabled()
            .filter_map(|r| self.signers[r].map(|signer| signer.key))
            .collect_vec()
    }

    pub fn get_allowed_destinations(&self, wallet_config: &WalletConfig) -> Vec<AddressBookEntry> {
        wallet_config
            .allowed_destinations
            .iter_enabled()
            .filter_map(|r| self.address_book[r])
            .collect_vec()
    }

    fn get_wallet_config_index(&self, wallet_guid_hash: &[u8; 32]) -> Result<usize, ProgramError> {
        self.wallets
            .iter()
            .position(|it| it.wallet_guid_hash == *wallet_guid_hash)
            .ok_or(WalletError::WalletNotFound.into())
    }

    pub fn get_wallet_config(
        &self,
        wallet_guid_hash: &[u8; 32],
    ) -> Result<&WalletConfig, ProgramError> {
        Ok(&self.wallets[self.get_wallet_config_index(wallet_guid_hash)?])
    }

    pub fn validate_config_initiator(&self, initiator: &AccountInfo) -> ProgramResult {
        return self.validate_initiator(initiator, || self.get_config_approvers_keys());
    }

    pub fn validate_transfer_initiator(
        &self,
        wallet_config: &WalletConfig,
        initiator: &AccountInfo,
    ) -> ProgramResult {
        return self.validate_initiator(initiator, || {
            self.get_transfer_approvers_keys(wallet_config)
        });
    }

    fn validate_initiator<F: FnOnce() -> Vec<Pubkey>>(
        &self,
        initiator: &AccountInfo,
        get_approvers: F,
    ) -> ProgramResult {
        if !initiator.is_signer {
            return Err(WalletError::InvalidSignature.into());
        }
        if initiator.key == &self.assistant.key || get_approvers().contains(initiator.key) {
            Ok(())
        } else {
            msg!("Transactions can only be initiated by an authorized account");
            Err(ProgramError::InvalidArgument)
        }
    }

    pub fn destination_allowed(
        &self,
        wallet_config: &WalletConfig,
        address: &Pubkey,
        name_hash: &[u8; 32],
    ) -> Result<bool, ProgramError> {
        Ok(
            match self.address_book.find_id(&AddressBookEntry {
                address: *address,
                name_hash: *name_hash,
            }) {
                Some(entry_ref) => wallet_config.allowed_destinations.is_enabled(&entry_ref),
                None => false,
            },
        )
    }

    pub fn validate_update(&self, config_update: &ProgramConfigUpdate) -> ProgramResult {
        let mut self_clone = self.clone();
        self_clone.update(config_update)
    }

    pub fn update(&mut self, config_update: &ProgramConfigUpdate) -> ProgramResult {
        self.approvals_required_for_config = config_update.approvals_required_for_config;
        if config_update.approval_timeout_for_config.as_secs() > 0 {
            self.approval_timeout_for_config = config_update.approval_timeout_for_config;
        }

        self.disable_config_approvers(&config_update.remove_config_approvers)?;
        self.remove_signers(&config_update.remove_signers)?;
        self.add_signers(&config_update.add_signers)?;
        self.enable_config_approvers(&config_update.add_config_approvers)?;
        self.remove_address_book_entries(&config_update.remove_address_book_entries)?;
        self.add_address_book_entries(&config_update.add_address_book_entries)?;

        let approvers_count_after_update = self.config_approvers.count_enabled();
        if usize::from(config_update.approvals_required_for_config) > approvers_count_after_update {
            msg!(
                "Approvals required for config {} can't exceed configured approvers count {}",
                config_update.approvals_required_for_config,
                approvers_count_after_update
            );
            return Err(ProgramError::InvalidArgument);
        }

        if self.approvals_required_for_config == 0 {
            msg!("Approvals required for config can't be 0");
            return Err(ProgramError::InvalidArgument);
        }

        if self.approval_timeout_for_config.as_secs() == 0 {
            msg!("Approvals timeout for config can't be 0");
            return Err(ProgramError::InvalidArgument);
        }

        if self.config_approvers.count_enabled() == 0 {
            msg!("At least one config approver has to be configured");
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    pub fn validate_add_wallet_config(
        &self,
        wallet_guid_hash: &[u8; 32],
        config_update: &WalletConfigUpdate,
    ) -> ProgramResult {
        let mut self_clone = self.clone();
        self_clone.add_wallet_config(wallet_guid_hash, config_update)
    }

    pub fn add_wallet_config(
        &mut self,
        wallet_guid_hash: &[u8; 32],
        config_update: &WalletConfigUpdate,
    ) -> ProgramResult {
        let wallet_config = WalletConfig {
            wallet_guid_hash: *wallet_guid_hash,
            wallet_name_hash: [0; 32],
            approvals_required_for_transfer: 0,
            approval_timeout_for_transfer: Duration::from_secs(0),
            transfer_approvers: Approvers::zero(),
            allowed_destinations: AllowedDestinations::zero(),
        };
        self.wallets.push(wallet_config);
        self.update_wallet_config(wallet_guid_hash, config_update)
    }

    pub fn validate_wallet_config_update(
        &self,
        wallet_guid_hash: &[u8; 32],
        config_update: &WalletConfigUpdate,
    ) -> ProgramResult {
        let mut self_clone = self.clone();
        self_clone.update_wallet_config(wallet_guid_hash, config_update)
    }

    pub fn update_wallet_config(
        &mut self,
        wallet_guid_hash: &[u8; 32],
        config_update: &WalletConfigUpdate,
    ) -> ProgramResult {
        let wallet_config_idx = self.get_wallet_config_index(wallet_guid_hash)?;

        self.disable_transfer_approvers(
            wallet_config_idx,
            &config_update.remove_transfer_approvers,
        )?;
        self.enable_transfer_approvers(wallet_config_idx, &config_update.add_transfer_approvers)?;
        self.disable_transfer_destinations(
            wallet_config_idx,
            &config_update.remove_allowed_destinations,
        )?;
        self.enable_transfer_destinations(
            wallet_config_idx,
            &config_update.add_allowed_destinations,
        )?;

        let wallet_config = &mut self.wallets[wallet_config_idx].borrow_mut();
        wallet_config.wallet_name_hash = config_update.name_hash;
        wallet_config.approvals_required_for_transfer =
            config_update.approvals_required_for_transfer;
        if config_update.approval_timeout_for_transfer.as_secs() > 0 {
            wallet_config.approval_timeout_for_transfer =
                config_update.approval_timeout_for_transfer;
        }

        let approvers_count_after_update = wallet_config.transfer_approvers.count_enabled();
        if usize::from(config_update.approvals_required_for_transfer) > approvers_count_after_update
        {
            msg!(
                "Approvals required for transfer {} can't exceed configured approvers count {}",
                config_update.approvals_required_for_transfer,
                approvers_count_after_update
            );
            return Err(ProgramError::InvalidArgument);
        }

        if wallet_config.approvals_required_for_transfer == 0 {
            msg!("Approvals required for transfer can't be 0");
            return Err(ProgramError::InvalidArgument);
        }

        if wallet_config.approval_timeout_for_transfer.as_secs() == 0 {
            msg!("Approvals timeout for transfer can't be 0");
            return Err(ProgramError::InvalidArgument);
        }

        if wallet_config.transfer_approvers.count_enabled() == 0 {
            msg!("At least one transfer approver has to be configured");
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    fn add_signers(&mut self, signers_to_add: &Vec<(SlotId<Signer>, Signer)>) -> ProgramResult {
        if !self.signers.can_be_inserted(signers_to_add) {
            msg!("Failed to add signers: at least on the provided slots is already taken");
            return Err(ProgramError::InvalidArgument);
        }
        self.signers.insert_many(signers_to_add);
        Ok(())
    }

    fn remove_signers(
        &mut self,
        signers_to_remove: &Vec<(SlotId<Signer>, Signer)>,
    ) -> ProgramResult {
        if !self.signers.can_be_removed(signers_to_remove) {
            msg!("Failed to remove signers: at least one of the provided signers is not present in the config");
            return Err(ProgramError::InvalidArgument);
        }
        let slot_ids = signers_to_remove.slot_ids();

        if self.config_approvers.any_enabled(&slot_ids) {
            msg!("Failed to remove signers: not allowed to remove a config approving signer");
            return Err(ProgramError::InvalidArgument);
        };
        for wallet_config in &self.wallets {
            if wallet_config.transfer_approvers.any_enabled(&slot_ids) {
                msg!("Failed to remove signers: not allowed to remove a transfer approving signer");
                return Err(ProgramError::InvalidArgument);
            }
        }
        self.signers.remove_many(signers_to_remove);
        Ok(())
    }

    fn add_address_book_entries(
        &mut self,
        entries_to_add: &Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    ) -> ProgramResult {
        if !self.address_book.can_be_inserted(entries_to_add) {
            msg!("Failed to add address book entries: at least on the provided slots is already taken");
            return Err(ProgramError::InvalidArgument);
        }
        self.address_book.insert_many(entries_to_add);
        Ok(())
    }

    fn remove_address_book_entries(
        &mut self,
        entries_to_remove: &Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    ) -> ProgramResult {
        if !self.address_book.can_be_removed(entries_to_remove) {
            msg!("Failed to remove address book entries: at least one of the provided entries is not present in the config");
            return Err(ProgramError::InvalidArgument);
        }
        let slot_ids = entries_to_remove.slot_ids();
        for wallet_config in &self.wallets {
            if wallet_config.allowed_destinations.any_enabled(&slot_ids) {
                msg!("Failed to remove address book entries: not allowed to remove an allowed address book entry");
                return Err(ProgramError::InvalidArgument);
            }
        }
        self.address_book.remove_many(entries_to_remove);
        Ok(())
    }

    fn enable_config_approvers(
        &mut self,
        approvers: &Vec<(SlotId<Signer>, Signer)>,
    ) -> ProgramResult {
        if !self.signers.contains(approvers) {
            msg!("Failed to enable config approvers: one of the given config approvers is not configured as signer");
            return Err(ProgramError::InvalidArgument);
        }
        self.config_approvers.enable_many(&approvers.slot_ids());
        Ok(())
    }

    fn disable_config_approvers(
        &mut self,
        approvers: &Vec<(SlotId<Signer>, Signer)>,
    ) -> ProgramResult {
        for (id, signer) in approvers {
            if self.signers[*id] == Some(*signer) || self.signers[*id] == None {
                self.config_approvers.disable(id);
            } else {
                msg!("Failed to disable config approvers: unexpected slot value");
                return Err(ProgramError::InvalidArgument);
            }
        }
        Ok(())
    }

    fn enable_transfer_approvers(
        &mut self,
        wallet_config_index: usize,
        approvers: &Vec<(SlotId<Signer>, Signer)>,
    ) -> ProgramResult {
        if !self.signers.contains(approvers) {
            msg!("Failed to enable transfer approvers: one of the given transfer approvers is not configured as signer");
            return Err(ProgramError::InvalidArgument);
        }
        self.wallets[wallet_config_index]
            .transfer_approvers
            .enable_many(&approvers.slot_ids());
        Ok(())
    }

    fn disable_transfer_approvers(
        &mut self,
        wallet_config_index: usize,
        approvers: &Vec<(SlotId<Signer>, Signer)>,
    ) -> ProgramResult {
        for (id, signer) in approvers {
            if self.signers[*id] == Some(*signer) || self.signers[*id] == None {
                self.wallets[wallet_config_index]
                    .transfer_approvers
                    .disable(id);
            } else {
                msg!("Failed to disable transfer approvers: unexpected slot value");
                return Err(ProgramError::InvalidArgument);
            }
        }
        Ok(())
    }

    fn enable_transfer_destinations(
        &mut self,
        wallet_config_index: usize,
        destinations: &Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    ) -> ProgramResult {
        if !self.address_book.contains(destinations) {
            msg!("Failed to enable transfer destinations: address book does not contain one of the given destinations");
            return Err(ProgramError::InvalidArgument);
        }
        self.wallets[wallet_config_index]
            .allowed_destinations
            .enable_many(&destinations.slot_ids());
        Ok(())
    }

    fn disable_transfer_destinations(
        &mut self,
        wallet_config_index: usize,
        destinations: &Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    ) -> ProgramResult {
        for (id, address_book_entry) in destinations {
            if self.address_book[*id] == Some(*address_book_entry) || self.address_book[*id] == None
            {
                self.wallets[wallet_config_index]
                    .allowed_destinations
                    .disable(id);
            } else {
                msg!("Failed to disable transfer destinations: unexpected slot value");
                return Err(ProgramError::InvalidArgument);
            }
        }
        Ok(())
    }
}

impl Pack for ProgramConfig {
    const LEN: usize = 1 + // is_initialized
        Signers::LEN +
        Signer::LEN + // assistant
        AddressBook::LEN +
        1 + // approvals_required_for_config
        8 + // approval_timeout_for_config
        Approvers::STORAGE_SIZE + // config approvers
        1 + WalletConfig::LEN * ProgramConfig::MAX_WALLETS; // wallets with size

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, ProgramConfig::LEN];
        let (
            is_initialized_dst,
            signers_dst,
            assistant_account_dst,
            address_book_dst,
            approvals_required_for_config_dst,
            approval_timeout_for_config_dst,
            config_approvers_dst,
            wallets_count_dst,
            wallets_dst,
        ) = mut_array_refs![
            dst,
            1,
            Signers::LEN,
            Signer::LEN,
            AddressBook::LEN,
            1,
            8,
            Approvers::STORAGE_SIZE,
            1,
            WalletConfig::LEN * ProgramConfig::MAX_WALLETS
        ];

        is_initialized_dst[0] = self.is_initialized as u8;

        self.signers.pack_into_slice(signers_dst);
        self.assistant.pack_into_slice(assistant_account_dst);
        self.address_book.pack_into_slice(address_book_dst);

        approvals_required_for_config_dst[0] = self.approvals_required_for_config;
        *approval_timeout_for_config_dst = self.approval_timeout_for_config.as_secs().to_le_bytes();

        config_approvers_dst.copy_from_slice(self.config_approvers.as_bytes());

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
            approval_timeout_for_config,
            config_approvers_src,
            wallets_count,
            wallets_src,
        ) = array_refs![
            src,
            1,
            Signers::LEN,
            Signer::LEN,
            AddressBook::LEN,
            1,
            8,
            Approvers::STORAGE_SIZE,
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
            approval_timeout_for_config: Duration::from_secs(u64::from_le_bytes(
                *approval_timeout_for_config,
            )),
            config_approvers: Approvers::new(*config_approvers_src),
            wallets,
        })
    }
}
