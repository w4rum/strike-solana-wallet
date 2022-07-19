use std::convert::TryInto;
use std::mem::size_of;
use std::slice::Iter;
use std::time::Duration;

use bitvec::macros::internal::funty::Fundamental;
use bytes::BufMut;
use solana_program::hash::Hash;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::Pack;
use solana_program::{instruction::AccountMeta, instruction::Instruction, pubkey::Pubkey};

use crate::constants::{HASH_LEN, PUBKEY_BYTES};
use crate::model::address_book::{AddressBookEntry, AddressBookEntryNameHash, DAppBookEntry};
use crate::model::balance_account::{
    BalanceAccount, BalanceAccountGuidHash, BalanceAccountNameHash,
};
use crate::model::multisig_op::{
    ApprovalDisposition, BooleanSetting, SlotUpdateType, WrapDirection,
};
use crate::model::signer::Signer;
use crate::model::wallet::WalletGuidHash;
use crate::serialization_utils::{
    append_duration, pack_option, read_account_guid_hash, read_account_name_hash,
    read_address_book_entry_name_hash, read_duration, read_fixed_size_array, read_slice, read_u16,
    read_u64, read_u8, unpack_option,
};
use crate::utils::SlotId;

// Instruction "tags" are sent as the first byte of each instruction
// and are mapped to corresponding ProgramInstructions to execute:
pub const TAG_INIT_WALLET: u8 = 0;
pub const TAG_INIT_BALANCE_ACCOUNT_CREATION: u8 = 3;
pub const TAG_FINALIZE_BALANCE_ACCOUNT_CREATION: u8 = 4;
pub const TAG_INIT_BALANCE_ACCOUNT_UPDATE: u8 = 5;
pub const TAG_FINALIZE_BALANCE_ACCOUNT_UPDATE: u8 = 6;
pub const TAG_INIT_TRANSFER: u8 = 7;
pub const TAG_FINALIZE_TRANSFER: u8 = 8;
pub const TAG_SET_APPROVAL_DISPOSITION: u8 = 9;
pub const TAG_INIT_WRAP_UNWRAP: u8 = 10;
pub const TAG_FINALIZE_WRAP_UNWRAP: u8 = 11;
pub const TAG_INIT_UPDATE_SIGNER: u8 = 12;
pub const TAG_FINALIZE_UPDATE_SIGNER: u8 = 13;
pub const TAG_INIT_WALLET_CONFIG_POLICY_UPDATE: u8 = 14;
pub const TAG_FINALIZE_WALLET_CONFIG_POLICY_UPDATE: u8 = 15;
pub const TAG_INIT_DAPP_TRANSACTION: u8 = 16;
pub const TAG_FINALIZE_DAPP_TRANSACTION: u8 = 17;
pub const TAG_INIT_ACCOUNT_SETTINGS_UPDATE: u8 = 18;
pub const TAG_FINALIZE_ACCOUNT_SETTINGS_UPDATE: u8 = 19;
pub const TAG_INIT_DAPP_BOOK_UPDATE: u8 = 20;
pub const TAG_FINALIZE_DAPP_BOOK_UPDATE: u8 = 21;
pub const TAG_INIT_ADDRESS_BOOK_UPDATE: u8 = 22;
pub const TAG_FINALIZE_ADDRESS_BOOK_UPDATE: u8 = 23;
pub const TAG_INIT_BALANCE_ACCOUNT_NAME_UPDATE: u8 = 24;
pub const TAG_FINALIZE_BALANCE_ACCOUNT_NAME_UPDATE: u8 = 25;
pub const TAG_INIT_BALANCE_ACCOUNT_POLICY_UPDATE: u8 = 26;
pub const TAG_FINALIZE_BALANCE_ACCOUNT_POLICY_UPDATE: u8 = 27;
pub const TAG_SUPPLY_DAPP_INSTRUCTIONS: u8 = 28;
pub const TAG_MIGRATE: u8 = 31;
pub const TAG_CLEANUP: u8 = 32;
pub const TAG_INIT_BALANCE_ACCOUNT_ADDRESS_WHITELIST_UPDATE: u8 = 33;
pub const TAG_FINALIZE_BALANCE_ACCOUNT_ADDRESS_WHITELIST_UPDATE: u8 = 34;
pub const TAG_INIT_SIGN_DATA: u8 = 35;
pub const TAG_FINALIZE_SIGN_DATA: u8 = 36;

#[derive(Debug)]
pub enum ProgramInstruction {
    /// 0. `[writable]` The wallet account
    /// 1. `[signer]` The transaction assistant account
    /// 2. `[signer]` The rent return account
    InitWallet {
        wallet_guid_hash: WalletGuidHash,
        initial_config: InitialWalletConfig,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitBalanceAccountCreation {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        account_guid_hash: BalanceAccountGuidHash,
        creation_params: BalanceAccountCreation,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 4. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeBalanceAccountCreation {
        account_guid_hash: BalanceAccountGuidHash,
        creation_params: BalanceAccountCreation,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[writable]` The source account
    /// 3. `[]` The destination account
    /// 4. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 5. `[]` The sysvar clock account
    /// 6. `[signer, writable]` The rent return account, also used if we need to create destination
    ///     token account for an SPL transfer and the source account does not have enough funds
    /// 7. `[]` The token mint (for SPL transfers, use system account otherwise)
    /// 8. `[writable]` The destination token account (only used for SPL transfers)
    /// 9. `[]` The system program (only used for SPL transfers)
    /// 10. `[]` The SPL token program (only used for SPL transfers)
    /// 11. `[]` The Rent sysvar program (only used for SPL transfers)
    /// 12. `[]` The SPL associated token program (only used for SPL transfers)
    InitTransfer {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        account_guid_hash: BalanceAccountGuidHash,
        amount: u64,
        destination_name_hash: AddressBookEntryNameHash,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[signer]` The approver account
    /// 2. `[]` The sysvar clock account
    SetApprovalDisposition {
        disposition: ApprovalDisposition,
        params_hash: Hash,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[writable]` The source account
    /// 3. `[writable]` The destination account
    /// 4. `[]` The system program
    /// 5. `[signer, writable]` The rent return account
    /// 6. `[]` The sysvar clock account
    /// 7. `[writable]` The source token account, if this is an SPL transfer
    /// 8. `[writable]` The destination token account, if this is an SPL transfer
    /// 9. `[]` The SPL token program account, if this is an SPL transfer
    /// 10. `[]` The token mint authority, if this is an SPL transfer
    /// 11. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 12. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeTransfer {
        account_guid_hash: BalanceAccountGuidHash,
        amount: u64,
        token_mint: Pubkey,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[writable]` The balance account
    /// 3. `[writable]` The associated wrapped SOL account
    /// 4. `[]` The native mint account
    /// 5. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 6. `[]` The sysvar clock account
    /// 7. `[signer]` The rent return account
    /// 8. `[writable]` A temporary wrapped SOL account (only for unwrap)
    /// 9. `[]` The system program
    /// 10. `[]` The SPL token program
    /// 11. `[]` The Rent sysvar program
    /// 12. `[]` The SPL associated token program
    InitWrapUnwrap {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        account_guid_hash: BalanceAccountGuidHash,
        amount: u64,
        direction: WrapDirection,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[writable]` The balance account
    /// 3. `[]` The system program
    /// 4. `[signer, writable]` The rent return account
    /// 5. `[]` The sysvar clock account
    /// 6. `[writable]` The wrapped SOL token account
    /// 7. `[]` The SPL token account
    /// 8. `[]` The native mint account
    /// 9. `[]` The SPL associated token program
    /// 10. `[writable]` A temporary wrapped SOL account, for use with unwrap
    /// 11. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    FinalizeWrapUnwrap {
        account_guid_hash: BalanceAccountGuidHash,
        amount: u64,
        direction: WrapDirection,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitUpdateSigner {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        slot_update_type: SlotUpdateType,
        slot_id: SlotId<Signer>,
        signer: Signer,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 4. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeUpdateSigner {
        slot_update_type: SlotUpdateType,
        slot_id: SlotId<Signer>,
        signer: Signer,
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitWalletConfigPolicyUpdate {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        update: WalletConfigPolicyUpdate,
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 4. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeWalletConfigPolicyUpdate { update: WalletConfigPolicyUpdate },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The multisig data account
    /// 2. `[]` The wallet account
    /// 3. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 4. `[]` The sysvar clock account
    /// 5. `[signer]` The rent return account
    InitDAppTransaction {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        account_guid_hash: BalanceAccountGuidHash,
        dapp: DAppBookEntry,
        instruction_count: u8,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The multisig data account
    /// 2. `[signer]` The initiator account
    SupplyDAppTransactionInstructions {
        instructions: Vec<Instruction>,
        starting_index: u8,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The multisig data account
    /// 2. `[]` The wallet account
    /// 3. `[writable]` The balance account
    /// 4. `[signer, writable]` The rent return account
    /// 5. `[]` The sysvar clock account
    /// 6. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 7. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeDAppTransaction {
        account_guid_hash: BalanceAccountGuidHash,
        params_hash: Hash,
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The initiator account
    InitAccountSettingsUpdate {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        account_guid_hash: BalanceAccountGuidHash,
        whitelist_enabled: Option<BooleanSetting>,
        dapps_enabled: Option<BooleanSetting>,
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 4. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeAccountSettingsUpdate {
        account_guid_hash: BalanceAccountGuidHash,
        whitelist_enabled: Option<BooleanSetting>,
        dapps_enabled: Option<BooleanSetting>,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitDAppBookUpdate {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        update: DAppBookUpdate,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[]` The sysvar clock account
    /// 4. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 5. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeDAppBookUpdate { update: DAppBookUpdate },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitAddressBookUpdate {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        update: AddressBookUpdate,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[]` The sysvar clock account
    /// 4. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 5. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeAddressBookUpdate { update: AddressBookUpdate },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitBalanceAccountNameUpdate {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        account_guid_hash: BalanceAccountGuidHash,
        account_name_hash: BalanceAccountNameHash,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[]` The sysvar clock account
    /// 4. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 5. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeBalanceAccountNameUpdate {
        account_guid_hash: BalanceAccountGuidHash,
        account_name_hash: BalanceAccountNameHash,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitBalanceAccountPolicyUpdate {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        account_guid_hash: BalanceAccountGuidHash,
        update: BalanceAccountPolicyUpdate,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[]` The sysvar clock account
    /// 4. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 5. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeBalanceAccountPolicyUpdate {
        account_guid_hash: BalanceAccountGuidHash,
        update: BalanceAccountPolicyUpdate,
    },

    /// 0. `[writable]` The source account to migrate from
    /// 1. `[writable]` The destination account to migrate to
    /// 2. `[signer]` The rent return account
    Migrate {},

    /// 0. `[]` The current wallet account
    /// 1. `[writable]` The wallet account to clean up
    /// 2. `[writable]` The rent return address
    Cleanup {},

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitBalanceAccountAddressWhitelistUpdate {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        account_guid_hash: BalanceAccountGuidHash,
        update: BalanceAccountAddressWhitelistUpdate,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[]` The sysvar clock account
    /// 4. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 5. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeBalanceAccountAddressWhitelistUpdate {
        account_guid_hash: BalanceAccountGuidHash,
        update: BalanceAccountAddressWhitelistUpdate,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[]` The wallet account
    /// 2. `[signer]` The initiator account
    /// 3. `[]` The sysvar clock account
    /// 4. `[signer]` The rent return account
    InitSignData {
        fee_amount: u64,
        fee_account_guid_hash: Option<BalanceAccountGuidHash>,
        data: Vec<u8>,
    },

    /// 0. `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet account
    /// 2. `[signer, writable]` The rent return account
    /// 3. `[]` The sysvar clock account
    /// 4. `[writable]` The fee account, if fee_account_guid_hash was set in the init
    /// 5. `[]` The system program (only needed if fee_account_guid_hash was set in the init)
    FinalizeSignData { data: Vec<u8> },
}

impl ProgramInstruction {
    /// Serialize a ProgramInstruction to a byte vector.
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(size_of::<Self>());
        match self {
            &ProgramInstruction::InitWallet {
                wallet_guid_hash,
                ref initial_config,
            } => {
                let mut initial_config_bytes: Vec<u8> = Vec::new();
                initial_config.pack(&mut initial_config_bytes);
                buf.push(TAG_INIT_WALLET);
                buf.extend_from_slice(wallet_guid_hash.to_bytes());
                buf.extend_from_slice(&initial_config_bytes);
            }
            &ProgramInstruction::InitBalanceAccountCreation {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                ref creation_params,
            } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                creation_params.pack(&mut update_bytes);
                buf.push(TAG_INIT_BALANCE_ACCOUNT_CREATION);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::FinalizeBalanceAccountCreation {
                ref account_guid_hash,
                ref creation_params,
            } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                creation_params.pack(&mut update_bytes);
                buf.push(TAG_FINALIZE_BALANCE_ACCOUNT_CREATION);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::InitTransfer {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                ref amount,
                ref destination_name_hash,
            } => {
                buf.push(TAG_INIT_TRANSFER);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(&amount.to_le_bytes());
                buf.extend_from_slice(destination_name_hash.to_bytes());
            }
            &ProgramInstruction::FinalizeTransfer {
                ref account_guid_hash,
                ref amount,
                ref token_mint,
            } => {
                buf.push(TAG_FINALIZE_TRANSFER);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(&amount.to_le_bytes());
                buf.extend_from_slice(&token_mint.to_bytes());
                buf.push(0);
            }
            &ProgramInstruction::SetApprovalDisposition {
                ref disposition,
                ref params_hash,
            } => {
                buf.push(TAG_SET_APPROVAL_DISPOSITION);
                buf.push(disposition.to_u8());
                buf.extend_from_slice(params_hash.as_ref());
            }
            &ProgramInstruction::InitWrapUnwrap {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                ref amount,
                ref direction,
            } => {
                buf.push(TAG_INIT_WRAP_UNWRAP);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(&account_guid_hash.to_bytes());
                buf.extend_from_slice(&amount.to_le_bytes());
                buf.push(direction.to_u8());
            }
            &ProgramInstruction::FinalizeWrapUnwrap {
                ref account_guid_hash,
                ref amount,
                ref direction,
            } => {
                buf.push(TAG_FINALIZE_WRAP_UNWRAP);
                buf.extend_from_slice(&account_guid_hash.to_bytes());
                buf.extend_from_slice(&amount.to_le_bytes());
                buf.push(direction.to_u8());
            }
            &ProgramInstruction::InitUpdateSigner {
                fee_amount,
                fee_account_guid_hash,
                ref slot_update_type,
                ref slot_id,
                ref signer,
            } => {
                buf.push(TAG_INIT_UPDATE_SIGNER);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.push(slot_update_type.to_u8());
                buf.push(slot_id.value as u8);
                buf.extend_from_slice(signer.key.as_ref());
            }
            &ProgramInstruction::FinalizeUpdateSigner {
                ref slot_update_type,
                ref slot_id,
                ref signer,
            } => {
                buf.push(TAG_FINALIZE_UPDATE_SIGNER);
                buf.push(slot_update_type.to_u8());
                buf.push(slot_id.value as u8);
                buf.extend_from_slice(signer.key.as_ref());
            }
            &ProgramInstruction::InitWalletConfigPolicyUpdate {
                fee_amount,
                fee_account_guid_hash,
                ref update,
            } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.push(TAG_INIT_WALLET_CONFIG_POLICY_UPDATE);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::FinalizeWalletConfigPolicyUpdate { ref update } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.push(TAG_FINALIZE_WALLET_CONFIG_POLICY_UPDATE);
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::InitDAppTransaction {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                ref dapp,
                instruction_count,
            } => {
                buf.push(TAG_INIT_DAPP_TRANSACTION);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(&account_guid_hash.to_bytes());
                let mut buf2 = vec![0; DAppBookEntry::LEN];
                dapp.pack_into_slice(buf2.as_mut_slice());
                buf.extend_from_slice(&buf2[..]);
                buf.put_u8(instruction_count);
            }
            &ProgramInstruction::FinalizeDAppTransaction {
                ref account_guid_hash,
                ref params_hash,
            } => {
                buf.push(TAG_FINALIZE_DAPP_TRANSACTION);
                buf.extend_from_slice(&account_guid_hash.to_bytes());
                buf.extend_from_slice(&params_hash.to_bytes());
            }
            &ProgramInstruction::InitAccountSettingsUpdate {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                ref whitelist_enabled,
                ref dapps_enabled,
            } => {
                buf.push(TAG_INIT_ACCOUNT_SETTINGS_UPDATE);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(&account_guid_hash.to_bytes());
                pack_option(whitelist_enabled.as_ref(), &mut buf);
                pack_option(dapps_enabled.as_ref(), &mut buf);
            }
            &ProgramInstruction::FinalizeAccountSettingsUpdate {
                ref account_guid_hash,
                ref whitelist_enabled,
                ref dapps_enabled,
            } => {
                buf.push(TAG_FINALIZE_ACCOUNT_SETTINGS_UPDATE);
                buf.extend_from_slice(&account_guid_hash.to_bytes());
                pack_option(whitelist_enabled.as_ref(), &mut buf);
                pack_option(dapps_enabled.as_ref(), &mut buf);
            }
            &ProgramInstruction::InitDAppBookUpdate {
                fee_amount,
                fee_account_guid_hash,
                ref update,
            } => {
                buf.push(TAG_INIT_DAPP_BOOK_UPDATE);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::FinalizeDAppBookUpdate { ref update } => {
                buf.push(TAG_FINALIZE_DAPP_BOOK_UPDATE);
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::InitAddressBookUpdate {
                fee_amount,
                fee_account_guid_hash,
                ref update,
            } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.push(TAG_INIT_ADDRESS_BOOK_UPDATE);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::FinalizeAddressBookUpdate { ref update } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.push(TAG_FINALIZE_ADDRESS_BOOK_UPDATE);
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::InitBalanceAccountNameUpdate {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                ref account_name_hash,
            } => {
                buf.push(TAG_INIT_BALANCE_ACCOUNT_NAME_UPDATE);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(account_name_hash.to_bytes());
            }
            &ProgramInstruction::FinalizeBalanceAccountNameUpdate {
                ref account_guid_hash,
                ref account_name_hash,
            } => {
                buf.push(TAG_FINALIZE_BALANCE_ACCOUNT_NAME_UPDATE);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(account_name_hash.to_bytes());
            }
            &ProgramInstruction::InitBalanceAccountPolicyUpdate {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                ref update,
            } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.push(TAG_INIT_BALANCE_ACCOUNT_POLICY_UPDATE);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::FinalizeBalanceAccountPolicyUpdate {
                ref account_guid_hash,
                ref update,
            } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.push(TAG_FINALIZE_BALANCE_ACCOUNT_POLICY_UPDATE);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::SupplyDAppTransactionInstructions {
                ref instructions,
                starting_index,
            } => {
                pack_supply_dapp_transaction_instructions(starting_index, instructions, &mut buf);
            }
            &ProgramInstruction::Migrate {} => {
                buf.push(TAG_MIGRATE);
            }
            &ProgramInstruction::Cleanup {} => {
                buf.push(TAG_CLEANUP);
            }
            &ProgramInstruction::InitBalanceAccountAddressWhitelistUpdate {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                ref update,
            } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.push(TAG_INIT_BALANCE_ACCOUNT_ADDRESS_WHITELIST_UPDATE);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::FinalizeBalanceAccountAddressWhitelistUpdate {
                ref account_guid_hash,
                ref update,
            } => {
                let mut update_bytes: Vec<u8> = Vec::new();
                update.pack(&mut update_bytes);
                buf.push(TAG_FINALIZE_BALANCE_ACCOUNT_ADDRESS_WHITELIST_UPDATE);
                buf.extend_from_slice(account_guid_hash.to_bytes());
                buf.extend_from_slice(&update_bytes);
            }
            &ProgramInstruction::InitSignData {
                fee_amount,
                fee_account_guid_hash,
                ref data,
            } => {
                buf.push(TAG_INIT_SIGN_DATA);
                buf.put_u64_le(fee_amount);
                pack_option(fee_account_guid_hash.as_ref(), &mut buf);
                buf.put_u16_le(data.len().as_u16());
                buf.extend_from_slice(data);
            }
            &ProgramInstruction::FinalizeSignData { ref data } => {
                buf.push(TAG_FINALIZE_SIGN_DATA);
                buf.put_u16_le(data.len().as_u16());
                buf.extend_from_slice(data);
            }
        }
        buf
    }

    /// Deserialize a byte buffer to ProgramInstruction.
    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let (tag, rest) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        Ok(match *tag {
            TAG_INIT_WALLET => Self::unpack_init_wallet_instruction(rest)?,

            TAG_INIT_BALANCE_ACCOUNT_CREATION => {
                Self::unpack_init_balance_account_creation_instruction(rest)?
            }
            TAG_FINALIZE_BALANCE_ACCOUNT_CREATION => {
                Self::unpack_finalize_balance_account_creation_instruction(rest)?
            }
            TAG_INIT_TRANSFER => Self::unpack_init_transfer_for_approval_instruction(rest)?,

            TAG_FINALIZE_TRANSFER => Self::unpack_finalize_transfer_instruction(rest)?,

            TAG_SET_APPROVAL_DISPOSITION => {
                Self::unpack_set_approval_disposition_instruction(rest)?
            }
            TAG_INIT_WRAP_UNWRAP => Self::unpack_init_wrap_unwrap_instruction(rest)?,

            TAG_FINALIZE_WRAP_UNWRAP => Self::unpack_finalize_wrap_unwrap_instruction(rest)?,

            TAG_INIT_UPDATE_SIGNER => Self::unpack_init_update_signer_instruction(rest)?,

            TAG_FINALIZE_UPDATE_SIGNER => Self::unpack_finalize_update_signer_instruction(rest)?,

            TAG_INIT_WALLET_CONFIG_POLICY_UPDATE => {
                Self::unpack_init_wallet_config_policy_update_instruction(rest)?
            }
            TAG_FINALIZE_WALLET_CONFIG_POLICY_UPDATE => {
                Self::unpack_finalize_wallet_config_policy_update_instruction(rest)?
            }
            TAG_INIT_DAPP_TRANSACTION => Self::unpack_init_dapp_transaction_instruction(rest)?,

            TAG_FINALIZE_DAPP_TRANSACTION => {
                Self::unpack_finalize_dapp_transaction_instruction(rest)?
            }
            TAG_INIT_ACCOUNT_SETTINGS_UPDATE => {
                Self::unpack_init_account_settings_update_instruction(rest)?
            }
            TAG_FINALIZE_ACCOUNT_SETTINGS_UPDATE => {
                Self::unpack_finalize_account_settings_update_instruction(rest)?
            }
            TAG_INIT_DAPP_BOOK_UPDATE => Self::unpack_init_dapp_book_update_instruction(rest)?,

            TAG_FINALIZE_DAPP_BOOK_UPDATE => {
                Self::unpack_finalize_dapp_book_update_instruction(rest)?
            }
            TAG_INIT_ADDRESS_BOOK_UPDATE => {
                Self::unpack_init_address_book_update_instruction(rest)?
            }
            TAG_FINALIZE_ADDRESS_BOOK_UPDATE => {
                Self::unpack_finalize_address_book_update_instruction(rest)?
            }
            TAG_INIT_BALANCE_ACCOUNT_NAME_UPDATE => {
                Self::unpack_init_balance_account_name_update_instruction(rest)?
            }
            TAG_FINALIZE_BALANCE_ACCOUNT_NAME_UPDATE => {
                Self::unpack_finalize_balance_account_name_update_instruction(rest)?
            }
            TAG_INIT_BALANCE_ACCOUNT_POLICY_UPDATE => {
                Self::unpack_init_balance_account_policy_update_instruction(rest)?
            }
            TAG_FINALIZE_BALANCE_ACCOUNT_POLICY_UPDATE => {
                Self::unpack_finalize_balance_account_policy_update_instruction(rest)?
            }
            TAG_SUPPLY_DAPP_INSTRUCTIONS => {
                Self::unpack_supply_dapp_instructions_instruction(rest)?
            }
            TAG_MIGRATE => Self::Migrate {},
            TAG_CLEANUP => Self::Cleanup {},
            TAG_INIT_BALANCE_ACCOUNT_ADDRESS_WHITELIST_UPDATE => {
                Self::unpack_init_balance_account_address_whitelist_update_instruction(rest)?
            }
            TAG_FINALIZE_BALANCE_ACCOUNT_ADDRESS_WHITELIST_UPDATE => {
                Self::unpack_finalize_balance_account_address_whitelist_update_instruction(rest)?
            }
            TAG_INIT_SIGN_DATA => Self::unpack_init_sign_data_instruction(rest)?,
            TAG_FINALIZE_SIGN_DATA => Self::unpack_finalize_sign_data_instruction(rest)?,
            _ => return Err(ProgramError::InvalidInstructionData),
        })
    }

    fn unpack_init_wallet_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::InitWallet {
            wallet_guid_hash: unpack_wallet_guid_hash(bytes)?,
            initial_config: InitialWalletConfig::unpack(
                bytes
                    .get(HASH_LEN..)
                    .ok_or(ProgramError::InvalidInstructionData)?,
            )?,
        })
    }

    fn unpack_init_balance_account_creation_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        Ok(Self::InitBalanceAccountCreation {
            fee_amount: read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?,
            fee_account_guid_hash: unpack_option::<BalanceAccountGuidHash>(iter)?,
            account_guid_hash: read_account_guid_hash(iter)
                .ok_or(ProgramError::InvalidInstructionData)?,
            creation_params: BalanceAccountCreation::unpack(iter.as_slice())?,
        })
    }

    fn unpack_finalize_balance_account_creation_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeBalanceAccountCreation {
            account_guid_hash: unpack_account_guid_hash(bytes)?,
            creation_params: BalanceAccountCreation::unpack(
                bytes
                    .get(HASH_LEN..)
                    .ok_or(ProgramError::InvalidInstructionData)?,
            )?,
        })
    }

    fn unpack_init_balance_account_policy_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        Ok(Self::InitBalanceAccountPolicyUpdate {
            fee_amount: read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?,
            fee_account_guid_hash: unpack_option::<BalanceAccountGuidHash>(iter)?,
            account_guid_hash: read_account_guid_hash(iter)
                .ok_or(ProgramError::InvalidInstructionData)?,
            update: BalanceAccountPolicyUpdate::unpack(iter.as_slice())?,
        })
    }

    fn unpack_finalize_balance_account_policy_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeBalanceAccountPolicyUpdate {
            account_guid_hash: unpack_account_guid_hash(bytes)?,
            update: BalanceAccountPolicyUpdate::unpack(
                bytes
                    .get(HASH_LEN..)
                    .ok_or(ProgramError::InvalidInstructionData)?,
            )?,
        })
    }

    fn unpack_init_transfer_for_approval_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;

        let account_guid_hash =
            read_account_guid_hash(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let destination_name_hash =
            read_address_book_entry_name_hash(iter).ok_or(ProgramError::InvalidInstructionData)?;

        Ok(Self::InitTransfer {
            fee_amount,
            fee_account_guid_hash,
            account_guid_hash,
            amount,
            destination_name_hash,
        })
    }

    fn unpack_set_approval_disposition_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let (disposition, rest) = bytes
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        Ok(Self::SetApprovalDisposition {
            disposition: ApprovalDisposition::from_u8(*disposition),
            params_hash: Hash::new_from_array(
                rest.get(0..HASH_LEN)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or(ProgramError::InvalidInstructionData)?,
            ),
        })
    }

    fn unpack_finalize_transfer_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeTransfer {
            account_guid_hash: unpack_account_guid_hash(bytes)?,
            amount: bytes
                .get(HASH_LEN..HASH_LEN + 8)
                .and_then(|slice| slice.try_into().ok())
                .map(u64::from_le_bytes)
                .ok_or(ProgramError::InvalidInstructionData)?,
            token_mint: unpack_public_key(bytes, HASH_LEN + 8)?,
        })
    }

    fn unpack_init_wrap_unwrap_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;
        let account_guid_hash =
            read_account_guid_hash(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let direction = read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;

        Ok(Self::InitWrapUnwrap {
            fee_amount,
            fee_account_guid_hash,
            account_guid_hash,
            amount,
            direction: WrapDirection::from_u8(*direction),
        })
    }

    fn unpack_finalize_wrap_unwrap_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        if let Some(direction) = bytes.get(40) {
            Ok(Self::FinalizeWrapUnwrap {
                account_guid_hash: unpack_account_guid_hash(bytes)?,
                amount: bytes
                    .get(HASH_LEN..HASH_LEN + 8)
                    .and_then(|slice| slice.try_into().ok())
                    .map(u64::from_le_bytes)
                    .ok_or(ProgramError::InvalidInstructionData)?,
                direction: WrapDirection::from_u8(*direction),
            })
        } else {
            Err(ProgramError::InvalidInstructionData)
        }
    }

    fn unpack_init_update_signer_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;
        let slot_update_type = read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let slot_id = read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
        Ok(Self::InitUpdateSigner {
            fee_amount,
            fee_account_guid_hash,
            slot_update_type: SlotUpdateType::from_u8(*slot_update_type),
            slot_id: SlotId::new(*slot_id as usize),
            signer: Signer::unpack_from_slice(iter.as_slice())?,
        })
    }

    fn unpack_finalize_update_signer_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let (slot_update_type, rest) = bytes
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        let (slot_id, rest) = rest
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        Ok(Self::FinalizeUpdateSigner {
            slot_update_type: SlotUpdateType::from_u8(*slot_update_type),
            slot_id: SlotId::new(*slot_id as usize),
            signer: Signer::unpack_from_slice(rest)?,
        })
    }

    fn unpack_init_wallet_config_policy_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;
        Ok(Self::InitWalletConfigPolicyUpdate {
            fee_amount,
            fee_account_guid_hash,
            update: WalletConfigPolicyUpdate::unpack(iter.as_slice())?,
        })
    }

    fn unpack_finalize_wallet_config_policy_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeWalletConfigPolicyUpdate {
            update: WalletConfigPolicyUpdate::unpack(bytes)?,
        })
    }

    fn unpack_init_dapp_transaction_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;
        let account_guid_hash = unpack_account_guid_hash(
            read_slice(iter, HASH_LEN).ok_or(ProgramError::InvalidInstructionData)?,
        )?;
        let dapp = DAppBookEntry::unpack_from_slice(
            read_slice(iter, DAppBookEntry::LEN).ok_or(ProgramError::InvalidInstructionData)?,
        )?;
        let instruction_count = read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
        Ok(Self::InitDAppTransaction {
            fee_amount,
            fee_account_guid_hash,
            account_guid_hash,
            dapp,
            instruction_count: *instruction_count,
        })
    }

    fn unpack_finalize_dapp_transaction_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let account_guid_hash = unpack_account_guid_hash(
            read_slice(iter, HASH_LEN).ok_or(ProgramError::InvalidInstructionData)?,
        )?;
        let params_hash =
            Hash::new(read_slice(iter, HASH_LEN).ok_or(ProgramError::InvalidInstructionData)?);
        Ok(Self::FinalizeDAppTransaction {
            account_guid_hash,
            params_hash,
        })
    }

    fn unpack_init_account_settings_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        Ok(Self::InitAccountSettingsUpdate {
            fee_amount: read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?,
            fee_account_guid_hash: unpack_option::<BalanceAccountGuidHash>(iter)?,
            account_guid_hash: read_account_guid_hash(iter)
                .ok_or(ProgramError::InvalidInstructionData)?,
            whitelist_enabled: unpack_option::<BooleanSetting>(iter)?,
            dapps_enabled: unpack_option::<BooleanSetting>(iter)?,
        })
    }

    fn unpack_finalize_account_settings_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        Ok(Self::FinalizeAccountSettingsUpdate {
            account_guid_hash: unpack_account_guid_hash(
                read_slice(iter, HASH_LEN).ok_or(ProgramError::InvalidInstructionData)?,
            )?,
            whitelist_enabled: unpack_option::<BooleanSetting>(iter)?,
            dapps_enabled: unpack_option::<BooleanSetting>(iter)?,
        })
    }

    fn unpack_init_dapp_book_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;
        Ok(Self::InitDAppBookUpdate {
            fee_amount,
            fee_account_guid_hash,
            update: DAppBookUpdate::unpack(iter.as_slice())?,
        })
    }

    fn unpack_finalize_dapp_book_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeDAppBookUpdate {
            update: DAppBookUpdate::unpack(bytes)?,
        })
    }

    fn unpack_init_address_book_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;
        Ok(Self::InitAddressBookUpdate {
            fee_amount,
            fee_account_guid_hash,
            update: AddressBookUpdate::unpack(iter.as_slice())?,
        })
    }

    fn unpack_finalize_address_book_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeAddressBookUpdate {
            update: AddressBookUpdate::unpack(bytes)?,
        })
    }

    fn unpack_init_balance_account_name_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        Ok(Self::InitBalanceAccountNameUpdate {
            fee_amount: read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?,
            fee_account_guid_hash: unpack_option::<BalanceAccountGuidHash>(iter)?,
            account_guid_hash: read_account_guid_hash(iter)
                .ok_or(ProgramError::InvalidInstructionData)?,
            account_name_hash: read_account_name_hash(iter)
                .ok_or(ProgramError::InvalidInstructionData)?,
        })
    }

    fn unpack_finalize_balance_account_name_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeBalanceAccountNameUpdate {
            account_guid_hash: unpack_account_guid_hash(bytes)?,
            account_name_hash: unpack_account_name_hash(
                bytes
                    .get(HASH_LEN..)
                    .ok_or(ProgramError::InvalidInstructionData)?,
            )?,
        })
    }

    fn unpack_supply_dapp_instructions_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let starting_index = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
        Ok(Self::SupplyDAppTransactionInstructions {
            starting_index,
            instructions: read_instructions(iter)?,
        })
    }

    fn unpack_init_balance_account_address_whitelist_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;
        let account_guid_hash =
            read_account_guid_hash(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let update = BalanceAccountAddressWhitelistUpdate::unpack(iter.as_slice())?;
        Ok(Self::InitBalanceAccountAddressWhitelistUpdate {
            fee_amount,
            fee_account_guid_hash,
            account_guid_hash,
            update,
        })
    }

    fn unpack_finalize_balance_account_address_whitelist_update_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeBalanceAccountAddressWhitelistUpdate {
            account_guid_hash: unpack_account_guid_hash(bytes)?,
            update: BalanceAccountAddressWhitelistUpdate::unpack(
                bytes
                    .get(HASH_LEN..)
                    .ok_or(ProgramError::InvalidInstructionData)?,
            )?,
        })
    }

    fn unpack_init_sign_data_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let fee_amount = read_u64(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let fee_account_guid_hash = unpack_option::<BalanceAccountGuidHash>(iter)?;
        let data_len = read_u16(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let data = read_slice(iter, data_len.try_into().unwrap())
            .ok_or(ProgramError::InvalidInstructionData)?
            .to_vec();
        Ok(Self::InitSignData {
            fee_amount,
            fee_account_guid_hash,
            data,
        })
    }

    fn unpack_finalize_sign_data_instruction(
        bytes: &[u8],
    ) -> Result<ProgramInstruction, ProgramError> {
        let iter = &mut bytes.into_iter();
        let data_len = read_u16(iter).ok_or(ProgramError::InvalidInstructionData)?;
        let data = read_slice(iter, data_len.try_into().unwrap())
            .ok_or(ProgramError::InvalidInstructionData)?
            .to_vec();
        Ok(Self::FinalizeSignData { data })
    }
}

pub fn pack_supply_dapp_transaction_instructions(
    starting_index: u8,
    instructions: &Vec<Instruction>,
    buf: &mut Vec<u8>,
) {
    buf.push(TAG_SUPPLY_DAPP_INSTRUCTIONS);
    buf.push(starting_index);
    buf.put_u16_le(instructions.len() as u16);
    for instruction in instructions.iter() {
        append_instruction(instruction, buf);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InitialWalletConfig {
    pub approvals_required_for_config: u8,
    pub approval_timeout_for_config: Duration,
    pub signers: Vec<(SlotId<Signer>, Signer)>,
    pub config_approvers: Vec<SlotId<Signer>>,
}

impl InitialWalletConfig {
    fn unpack(bytes: &[u8]) -> Result<InitialWalletConfig, ProgramError> {
        if bytes.len() < 7 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut iter = bytes.iter();
        let approvals_required_for_config =
            *iter.next().ok_or(ProgramError::InvalidInstructionData)?;
        let approval_timeout_for_config =
            read_duration(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let signers = read_signers(&mut iter)?;
        let config_approvers = read_signer_slots(&mut iter)?;

        Ok(InitialWalletConfig {
            approvals_required_for_config,
            approval_timeout_for_config,
            signers,
            config_approvers,
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        dst.push(self.approvals_required_for_config);
        append_duration(&self.approval_timeout_for_config, dst);
        append_signers(&self.signers, dst);
        append_signer_slots(&self.config_approvers, dst);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BalanceAccountWhitelistUpdate {
    pub guid_hash: BalanceAccountGuidHash,
    pub add_allowed_destinations: Vec<SlotId<AddressBookEntry>>,
    pub remove_allowed_destinations: Vec<SlotId<AddressBookEntry>>,
    pub destinations_hash: Hash,
}

impl BalanceAccountWhitelistUpdate {
    fn unpack_from_slice(
        iter: &mut Iter<u8>,
    ) -> Result<BalanceAccountWhitelistUpdate, ProgramError> {
        Ok(BalanceAccountWhitelistUpdate {
            guid_hash: unpack_account_guid_hash(
                read_slice(iter, HASH_LEN).ok_or(ProgramError::InvalidInstructionData)?,
            )?,
            add_allowed_destinations: read_address_book_entries_slots(iter)?,
            remove_allowed_destinations: read_address_book_entries_slots(iter)?,
            destinations_hash: Hash::new_from_array(
                *read_fixed_size_array(iter).ok_or(ProgramError::InvalidInstructionData)?,
            ),
        })
    }

    pub fn pack_into_slice(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.guid_hash.to_bytes());
        append_address_book_entries_slots(&self.add_allowed_destinations, dst);
        append_address_book_entries_slots(&self.remove_allowed_destinations, dst);
        dst.extend_from_slice(self.destinations_hash.as_ref());
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BalanceAccountAddressWhitelistUpdate {
    pub allowed_destinations: Vec<SlotId<AddressBookEntry>>,
    pub destinations_hash: Hash,
}

impl BalanceAccountAddressWhitelistUpdate {
    pub fn unpack(bytes: &[u8]) -> Result<BalanceAccountAddressWhitelistUpdate, ProgramError> {
        let mut iter = bytes.iter();
        Ok(BalanceAccountAddressWhitelistUpdate {
            allowed_destinations: read_address_book_entries_slots(&mut iter)?,
            destinations_hash: Hash::new_from_array(
                *read_fixed_size_array(&mut iter).ok_or(ProgramError::InvalidInstructionData)?,
            ),
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        append_address_book_entries_slots(&self.allowed_destinations, dst);
        dst.extend_from_slice(self.destinations_hash.as_ref());
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddressBookUpdate {
    pub add_address_book_entries: Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    pub remove_address_book_entries: Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    pub balance_account_whitelist_updates: Vec<BalanceAccountWhitelistUpdate>,
}

impl AddressBookUpdate {
    fn unpack(bytes: &[u8]) -> Result<AddressBookUpdate, ProgramError> {
        let mut iter = bytes.iter();

        let add_address_book_entries = read_address_book_entries(&mut iter)?;
        let remove_address_book_entries = read_address_book_entries(&mut iter)?;
        let balance_account_whitelist_updates = read_balance_account_whitelist_updates(&mut iter)?;

        Ok(AddressBookUpdate {
            add_address_book_entries,
            remove_address_book_entries,
            balance_account_whitelist_updates,
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        append_address_book_entries(&self.add_address_book_entries, dst);
        append_address_book_entries(&self.remove_address_book_entries, dst);
        append_balance_account_whitelist_updates(&self.balance_account_whitelist_updates, dst);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WalletConfigPolicyUpdate {
    pub approvals_required_for_config: u8,
    pub approval_timeout_for_config: Duration,
    pub config_approvers: Vec<SlotId<Signer>>,
    pub signers_hash: Hash,
}

impl WalletConfigPolicyUpdate {
    fn unpack(bytes: &[u8]) -> Result<WalletConfigPolicyUpdate, ProgramError> {
        let mut iter = bytes.iter();
        let approvals_required_for_config =
            *read_u8(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let approval_timeout_for_config =
            read_duration(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let config_approvers = read_signer_slots(&mut iter)?;
        let signers_hash: [u8; HASH_LEN] =
            *read_fixed_size_array(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;

        Ok(WalletConfigPolicyUpdate {
            approvals_required_for_config,
            approval_timeout_for_config,
            config_approvers,
            signers_hash: Hash::new_from_array(signers_hash),
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        dst.push(self.approvals_required_for_config);
        append_duration(&self.approval_timeout_for_config, dst);
        append_signer_slots(&self.config_approvers, dst);
        dst.extend_from_slice(self.signers_hash.as_ref());
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BalanceAccountCreation {
    pub slot_id: SlotId<BalanceAccount>,
    pub name_hash: BalanceAccountNameHash,
    pub approvals_required_for_transfer: u8,
    pub approval_timeout_for_transfer: Duration,
    pub transfer_approvers: Vec<SlotId<Signer>>,
    pub signers_hash: Hash,
    pub whitelist_enabled: BooleanSetting,
    pub dapps_enabled: BooleanSetting,
    pub address_book_slot_id: SlotId<AddressBookEntry>,
}

impl BalanceAccountCreation {
    fn unpack(bytes: &[u8]) -> Result<BalanceAccountCreation, ProgramError> {
        if bytes.len() < 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut iter = bytes.iter();
        let slot_id = *iter.next().ok_or(ProgramError::InvalidInstructionData)?;
        let name_hash: [u8; HASH_LEN] =
            *read_fixed_size_array(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let approvals_required_for_transfer =
            *read_u8(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let approval_timeout_for_transfer =
            read_duration(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let transfer_approvers = read_signer_slots(&mut iter)?;
        let signers_hash: [u8; HASH_LEN] =
            *read_fixed_size_array(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let whitelist_enabled = *iter.next().ok_or(ProgramError::InvalidInstructionData)?;
        let dapps_enabled = *iter.next().ok_or(ProgramError::InvalidInstructionData)?;
        let address_book_slot_id = *iter.next().ok_or(ProgramError::InvalidInstructionData)?;

        Ok(BalanceAccountCreation {
            slot_id: SlotId::new(slot_id as usize),
            name_hash: BalanceAccountNameHash::new(&name_hash),
            approvals_required_for_transfer,
            approval_timeout_for_transfer,
            transfer_approvers,
            signers_hash: Hash::new_from_array(signers_hash),
            whitelist_enabled: BooleanSetting::from_u8(whitelist_enabled),
            dapps_enabled: BooleanSetting::from_u8(dapps_enabled),
            address_book_slot_id: SlotId::new(address_book_slot_id as usize),
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        dst.push(self.slot_id.value as u8);
        dst.extend_from_slice(self.name_hash.to_bytes());
        dst.push(self.approvals_required_for_transfer);
        append_duration(&self.approval_timeout_for_transfer, dst);
        append_signer_slots(&self.transfer_approvers, dst);
        dst.extend_from_slice(self.signers_hash.as_ref());
        dst.push(self.whitelist_enabled.to_u8());
        dst.push(self.dapps_enabled.to_u8());
        dst.push(self.address_book_slot_id.value as u8);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BalanceAccountPolicyUpdate {
    pub approvals_required_for_transfer: u8,
    pub approval_timeout_for_transfer: Duration,
    pub transfer_approvers: Vec<SlotId<Signer>>,
    pub signers_hash: Hash,
}

impl BalanceAccountPolicyUpdate {
    fn unpack(bytes: &[u8]) -> Result<BalanceAccountPolicyUpdate, ProgramError> {
        if bytes.len() < 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut iter = bytes.iter();
        let approvals_required_for_transfer =
            *read_u8(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let approval_timeout_for_transfer =
            read_duration(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let approvers = read_signer_slots(&mut iter)?;
        let signers_hash: [u8; HASH_LEN] =
            *read_fixed_size_array(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;

        Ok(BalanceAccountPolicyUpdate {
            approvals_required_for_transfer,
            approval_timeout_for_transfer,
            transfer_approvers: approvers,
            signers_hash: Hash::new_from_array(signers_hash),
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        dst.push(self.approvals_required_for_transfer);
        append_duration(&self.approval_timeout_for_transfer, dst);
        append_signer_slots(&self.transfer_approvers, dst);
        dst.extend_from_slice(self.signers_hash.as_ref());
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DAppBookUpdate {
    pub add_dapps: Vec<(SlotId<DAppBookEntry>, DAppBookEntry)>,
    pub remove_dapps: Vec<(SlotId<DAppBookEntry>, DAppBookEntry)>,
}

impl DAppBookUpdate {
    fn unpack(bytes: &[u8]) -> Result<DAppBookUpdate, ProgramError> {
        if bytes.len() < 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut iter = bytes.iter();
        let add_dapps = read_address_book_entries(&mut iter)?;
        let remove_dapps = read_address_book_entries(&mut iter)?;

        Ok(DAppBookUpdate {
            add_dapps,
            remove_dapps,
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        append_address_book_entries(&self.add_dapps, dst);
        append_address_book_entries(&self.remove_dapps, dst);
    }
}

fn read_signers(iter: &mut Iter<u8>) -> Result<Vec<(SlotId<Signer>, Signer)>, ProgramError> {
    let signers_count = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
    read_slice(iter, usize::from(signers_count) * (1 + Signer::LEN))
        .ok_or(ProgramError::InvalidInstructionData)?
        .chunks_exact(1 + Signer::LEN)
        .map(|chunk| {
            Signer::unpack_from_slice(&chunk[1..1 + Signer::LEN])
                .map(|signer| (SlotId::new(usize::from(chunk[0])), signer))
        })
        .collect()
}

fn read_signer_slots(iter: &mut Iter<u8>) -> Result<Vec<SlotId<Signer>>, ProgramError> {
    let signers_count = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)? as usize;
    let mut slots: Vec<SlotId<Signer>> = Vec::with_capacity(signers_count);
    for _ in 0..signers_count {
        slots.push(SlotId::new(usize::from(
            *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?,
        )))
    }
    Ok(slots)
}

fn append_signers(signers: &Vec<(SlotId<Signer>, Signer)>, dst: &mut Vec<u8>) {
    dst.push(signers.len() as u8);
    for (slot_id, signer) in signers.iter() {
        let mut buf = vec![0; 1 + Signer::LEN];
        buf[0] = slot_id.value as u8;
        signer.pack_into_slice(&mut buf[1..1 + Signer::LEN]);
        dst.extend_from_slice(buf.as_slice());
    }
}

fn append_signer_slots(signers: &Vec<SlotId<Signer>>, dst: &mut Vec<u8>) {
    dst.push(signers.len() as u8);
    for slot_id in signers.iter() {
        dst.push(slot_id.value as u8);
    }
}

fn read_account_guid_vec(iter: &mut Iter<u8>) -> Result<Vec<BalanceAccountGuidHash>, ProgramError> {
    let n = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
    Ok((0..n).map(|_| read_account_guid(iter).unwrap()).collect())
}

fn read_account_guid(iter: &mut Iter<u8>) -> Result<BalanceAccountGuidHash, ProgramError> {
    unpack_account_guid_hash(
        read_slice(iter, HASH_LEN)
            .ok_or(ProgramError::InvalidInstructionData)?
            .into(),
    )
}

fn read_instructions(iter: &mut Iter<u8>) -> Result<Vec<Instruction>, ProgramError> {
    let instruction_count = read_u16(iter).ok_or(ProgramError::InvalidInstructionData)?;
    Ok((0..instruction_count)
        .map(|_| read_instruction(iter).unwrap())
        .collect())
}

fn read_account_meta(iter: &mut Iter<u8>) -> Result<AccountMeta, ProgramError> {
    let flags = *read_u8(iter)
        .ok_or(ProgramError::InvalidInstructionData)
        .unwrap();
    let pubkey = Pubkey::new(
        read_slice(iter, PUBKEY_BYTES)
            .ok_or(ProgramError::InvalidInstructionData)
            .unwrap()
            .try_into()
            .ok()
            .unwrap(),
    );
    Ok(AccountMeta {
        is_writable: (flags & 1) == 1,
        is_signer: (flags & 2) == 2,
        pubkey,
    })
}

pub fn read_instruction(iter: &mut Iter<u8>) -> Result<Instruction, ProgramError> {
    let pubkey_bytes = read_slice(iter, PUBKEY_BYTES).ok_or(ProgramError::InvalidAccountData)?;
    let program_id = Pubkey::new(pubkey_bytes);
    let account_meta_count = read_u16(iter).ok_or(ProgramError::InvalidInstructionData)?;
    let accounts = (0..account_meta_count)
        .map(|_| read_account_meta(iter).unwrap())
        .collect();

    let data_len = read_u16(iter).ok_or(ProgramError::InvalidInstructionData)?;
    let data = read_slice(iter, data_len.try_into().unwrap())
        .ok_or(ProgramError::InvalidInstructionData)?
        .to_vec();

    Ok(Instruction {
        program_id,
        accounts,
        data,
    })
}

pub fn read_instruction_from_slice(slice: &[u8]) -> Result<Instruction, ProgramError> {
    // first check that it is big enough for program id and account meta count
    if slice.len() < PUBKEY_BYTES + 2 {
        return Err(ProgramError::InvalidAccountData);
    }
    let program_id = Pubkey::new(&slice[0..PUBKEY_BYTES]);
    let mut u16_len: [u8; 2] = [0; 2];
    u16_len.copy_from_slice(&slice[PUBKEY_BYTES..PUBKEY_BYTES + 2]);
    let account_meta_count = usize::from(u16::from_le_bytes(u16_len));
    // now check that it is big enough for all account metas + data len
    if slice.len() < PUBKEY_BYTES + 2 + account_meta_count * (PUBKEY_BYTES + 1) + 2 {
        return Err(ProgramError::InvalidAccountData);
    }
    let accounts = (0..account_meta_count)
        .map(|ix| {
            let account_meta_start = PUBKEY_BYTES + 2 + ix * (PUBKEY_BYTES + 1);
            let flags = slice[account_meta_start];
            let pubkey =
                Pubkey::new(&slice[account_meta_start + 1..account_meta_start + 1 + PUBKEY_BYTES]);
            AccountMeta {
                is_writable: (flags & 1) == 1,
                is_signer: (flags & 2) == 2,
                pubkey,
            }
        })
        .collect();
    let data_len_start = PUBKEY_BYTES + 2 + account_meta_count * (PUBKEY_BYTES + 1);
    u16_len.copy_from_slice(&slice[data_len_start..data_len_start + 2]);
    let data_len = usize::from(u16::from_le_bytes(u16_len));
    if slice.len() < data_len_start + 2 + data_len {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(Instruction {
        program_id,
        accounts,
        data: slice[data_len_start + 2..data_len_start + 2 + data_len].to_vec(),
    })
}

pub fn append_instruction(instruction: &Instruction, dst: &mut Vec<u8>) {
    dst.extend_from_slice(instruction.program_id.as_ref());
    dst.put_u16_le(instruction.accounts.len() as u16);
    for account in instruction.accounts.iter() {
        let mut buf = vec![0; 1 + Signer::LEN];
        buf[0] = 0;
        if account.is_signer {
            buf[0] |= 2;
        }
        if account.is_writable {
            buf[0] |= 1;
        }
        Signer::new(account.pubkey).pack_into_slice(&mut buf[1..1 + Signer::LEN]);
        dst.extend_from_slice(buf.as_slice());
    }
    dst.put_u16_le(instruction.data.len().as_u16());
    dst.extend_from_slice(instruction.data.as_slice());
}

fn read_address_book_entries(
    iter: &mut Iter<u8>,
) -> Result<Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>, ProgramError> {
    let entries_count = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
    read_slice(
        iter,
        usize::from(entries_count) * (1 + AddressBookEntry::LEN),
    )
    .ok_or(ProgramError::InvalidInstructionData)?
    .chunks_exact(1 + AddressBookEntry::LEN)
    .map(|chunk| {
        AddressBookEntry::unpack_from_slice(&chunk[1..1 + AddressBookEntry::LEN])
            .map(|entry| (SlotId::new(usize::from(chunk[0])), entry))
    })
    .collect()
}

fn append_address_book_entries(
    entries: &Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    dst: &mut Vec<u8>,
) {
    dst.push(entries.len() as u8);
    for (slot_id, entry) in entries.iter() {
        let mut buf = vec![0; 1 + AddressBookEntry::LEN];
        buf[0] = slot_id.value as u8;
        entry.pack_into_slice(&mut buf[1..1 + AddressBookEntry::LEN]);
        dst.extend_from_slice(buf.as_slice());
    }
}

fn read_address_book_entries_slots(
    iter: &mut Iter<u8>,
) -> Result<Vec<SlotId<AddressBookEntry>>, ProgramError> {
    let entries_count = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)? as usize;
    let mut slots: Vec<SlotId<AddressBookEntry>> = Vec::with_capacity(entries_count);
    for _ in 0..entries_count {
        slots.push(SlotId::new(usize::from(
            *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?,
        )))
    }
    Ok(slots)
}

fn append_address_book_entries_slots(entries: &Vec<SlotId<AddressBookEntry>>, dst: &mut Vec<u8>) {
    dst.push(entries.len() as u8);
    for slot_id in entries.iter() {
        dst.push(slot_id.value as u8);
    }
}

pub fn unpack_account_guid_hash_vec(
    bytes: &[u8],
) -> Result<Vec<BalanceAccountGuidHash>, ProgramError> {
    let iter = &mut bytes.iter();
    read_account_guid_vec(iter)
}

fn unpack_wallet_guid_hash(bytes: &[u8]) -> Result<WalletGuidHash, ProgramError> {
    bytes
        .get(..HASH_LEN)
        .and_then(|slice| {
            slice
                .try_into()
                .ok()
                .map(|bytes| WalletGuidHash::new(bytes))
        })
        .ok_or(ProgramError::InvalidInstructionData)
}

fn unpack_account_guid_hash(bytes: &[u8]) -> Result<BalanceAccountGuidHash, ProgramError> {
    bytes
        .get(..HASH_LEN)
        .and_then(|slice| {
            slice
                .try_into()
                .ok()
                .map(|bytes| BalanceAccountGuidHash::new(bytes))
        })
        .ok_or(ProgramError::InvalidInstructionData)
}

fn unpack_account_name_hash(bytes: &[u8]) -> Result<BalanceAccountNameHash, ProgramError> {
    bytes
        .get(..HASH_LEN)
        .and_then(|slice| {
            slice
                .try_into()
                .ok()
                .map(|bytes| BalanceAccountNameHash::new(bytes))
        })
        .ok_or(ProgramError::InvalidInstructionData)
}

/// Deserialize a Pubkey, starting from the given offset in `bytes` slice.
fn unpack_public_key(bytes: &[u8], offset: usize) -> Result<Pubkey, ProgramError> {
    Ok(Pubkey::new_from_array(
        bytes
            .get(offset..offset + PUBKEY_BYTES)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(ProgramError::InvalidInstructionData)?,
    ))
}

fn append_balance_account_whitelist_updates(
    entries: &Vec<BalanceAccountWhitelistUpdate>,
    dst: &mut Vec<u8>,
) {
    dst.push(entries.len() as u8);
    for entry in entries.iter() {
        entry.pack_into_slice(dst);
    }
}

fn read_balance_account_whitelist_updates(
    iter: &mut Iter<u8>,
) -> Result<Vec<BalanceAccountWhitelistUpdate>, ProgramError> {
    let entries_count = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)? as usize;
    let mut updates: Vec<BalanceAccountWhitelistUpdate> = Vec::with_capacity(entries_count);
    for _ in 0..entries_count {
        updates.push(BalanceAccountWhitelistUpdate::unpack_from_slice(iter)?)
    }
    Ok(updates)
}

pub fn pack_balance_account_guid_hash_vec(hashes: &Vec<BalanceAccountGuidHash>, buf: &mut Vec<u8>) {
    buf.put_u8(hashes.len() as u8);
    for h in hashes.iter() {
        buf.extend_from_slice(h.to_bytes());
    }
}
