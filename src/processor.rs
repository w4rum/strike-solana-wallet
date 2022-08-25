use crate::handlers::{
    address_book_update_handler, approval_disposition_handler,
    balance_account_address_whitelist_update_handler, balance_account_creation_handler,
    balance_account_name_update_handler, balance_account_policy_update_handler,
    balance_account_settings_update_handler, cleanup_handler, dapp_book_update_handler,
    dapp_transaction_handler, init_wallet_handler, migrate_handler, sign_data_handler,
    transfer_handler, update_signer_handler, wallet_config_policy_update_handler,
    wrap_unwrap_handler,
};
use crate::instruction::ProgramInstruction;
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};

pub struct Processor;

impl Processor {
    pub fn process(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let instruction = ProgramInstruction::unpack(instruction_data)?;

        match instruction {
            ProgramInstruction::InitWallet {
                wallet_guid_hash,
                initial_config,
            } => init_wallet_handler::handle(
                program_id,
                accounts,
                &wallet_guid_hash,
                &initial_config,
            ),

            ProgramInstruction::InitWalletConfigPolicyUpdate {
                fee_amount,
                fee_account_guid_hash,
                update,
            } => wallet_config_policy_update_handler::init(
                program_id,
                accounts,
                fee_amount,
                fee_account_guid_hash,
                &update,
            ),

            ProgramInstruction::FinalizeWalletConfigPolicyUpdate { update } => {
                wallet_config_policy_update_handler::finalize(program_id, accounts, &update)
            }

            ProgramInstruction::InitBalanceAccountCreation {
                fee_amount,
                fee_account_guid_hash,
                account_guid_hash,
                creation_params,
            } => balance_account_creation_handler::init(
                program_id,
                accounts,
                fee_amount,
                fee_account_guid_hash,
                &account_guid_hash,
                &creation_params,
            ),

            ProgramInstruction::FinalizeBalanceAccountCreation {
                account_guid_hash,
                creation_params,
            } => balance_account_creation_handler::finalize(
                program_id,
                accounts,
                &account_guid_hash,
                &creation_params,
            ),

            ProgramInstruction::InitBalanceAccountNameUpdate {
                fee_amount,
                fee_account_guid_hash,
                account_guid_hash,
                account_name_hash,
            } => balance_account_name_update_handler::init(
                program_id,
                accounts,
                fee_amount,
                fee_account_guid_hash,
                &account_guid_hash,
                &account_name_hash,
            ),

            ProgramInstruction::FinalizeBalanceAccountNameUpdate {
                account_guid_hash,
                account_name_hash,
            } => balance_account_name_update_handler::finalize(
                program_id,
                accounts,
                &account_guid_hash,
                &account_name_hash,
            ),

            ProgramInstruction::InitBalanceAccountPolicyUpdate {
                fee_amount,
                fee_account_guid_hash,
                account_guid_hash,
                update,
            } => balance_account_policy_update_handler::init(
                program_id,
                accounts,
                fee_amount,
                fee_account_guid_hash,
                &account_guid_hash,
                &update,
            ),

            ProgramInstruction::FinalizeBalanceAccountPolicyUpdate {
                account_guid_hash,
                update,
            } => balance_account_policy_update_handler::finalize(
                program_id,
                accounts,
                &account_guid_hash,
                &update,
            ),

            ProgramInstruction::InitTransfer {
                fee_amount,
                fee_account_guid_hash,
                account_guid_hash,
                amount,
                destination_name_hash,
            } => transfer_handler::init(
                program_id,
                &accounts,
                fee_amount,
                fee_account_guid_hash,
                &account_guid_hash,
                amount,
                &destination_name_hash,
            ),

            ProgramInstruction::FinalizeTransfer {
                account_guid_hash,
                amount,
                token_mint,
            } => transfer_handler::finalize(
                program_id,
                &accounts,
                &account_guid_hash,
                amount,
                token_mint,
            ),

            ProgramInstruction::SetApprovalDisposition {
                disposition,
                params_hash,
            } => approval_disposition_handler::handle(
                program_id,
                &accounts,
                disposition,
                params_hash,
            ),

            ProgramInstruction::InitWrapUnwrap {
                fee_amount,
                fee_account_guid_hash,
                account_guid_hash,
                amount,
                direction,
            } => wrap_unwrap_handler::init(
                program_id,
                &accounts,
                fee_amount,
                fee_account_guid_hash,
                &account_guid_hash,
                amount,
                direction,
            ),

            ProgramInstruction::FinalizeWrapUnwrap {
                account_guid_hash,
                amount,
                direction,
            } => wrap_unwrap_handler::finalize(
                program_id,
                &accounts,
                &account_guid_hash,
                amount,
                direction,
            ),

            ProgramInstruction::InitUpdateSigner {
                fee_amount,
                fee_account_guid_hash,
                slot_update_type,
                slot_id,
                signer,
            } => update_signer_handler::init(
                program_id,
                &accounts,
                fee_amount,
                fee_account_guid_hash,
                slot_update_type,
                slot_id,
                signer,
            ),

            ProgramInstruction::FinalizeUpdateSigner {
                slot_update_type,
                slot_id,
                signer,
            } => update_signer_handler::finalize(
                program_id,
                &accounts,
                slot_update_type,
                slot_id,
                signer,
            ),

            ProgramInstruction::InitDAppTransaction {
                fee_amount,
                fee_account_guid_hash,
                ref account_guid_hash,
                dapp,
                total_instruction_len,
            } => dapp_transaction_handler::init(
                program_id,
                accounts,
                fee_amount,
                fee_account_guid_hash,
                account_guid_hash,
                dapp,
                total_instruction_len,
            ),

            ProgramInstruction::SupplyDAppTransactionInstructions {
                instruction_data,
                instruction_data_offset,
                instruction_data_len,
            } => dapp_transaction_handler::supply_instructions(
                program_id,
                accounts,
                instruction_data_offset,
                instruction_data_len,
                instruction_data,
            ),

            ProgramInstruction::FinalizeDAppTransaction {} => {
                dapp_transaction_handler::finalize(program_id, accounts)
            }

            ProgramInstruction::InitAccountSettingsUpdate {
                fee_amount,
                fee_account_guid_hash,
                account_guid_hash,
                whitelist_enabled,
                dapps_enabled,
            } => balance_account_settings_update_handler::init(
                program_id,
                &accounts,
                fee_amount,
                fee_account_guid_hash,
                &account_guid_hash,
                whitelist_enabled,
                dapps_enabled,
            ),

            ProgramInstruction::FinalizeAccountSettingsUpdate {
                account_guid_hash,
                whitelist_enabled,
                dapps_enabled,
            } => balance_account_settings_update_handler::finalize(
                program_id,
                &accounts,
                &account_guid_hash,
                whitelist_enabled,
                dapps_enabled,
            ),

            ProgramInstruction::InitDAppBookUpdate {
                fee_amount,
                fee_account_guid_hash,
                update,
            } => dapp_book_update_handler::init(
                program_id,
                &accounts,
                fee_amount,
                fee_account_guid_hash,
                &update,
            ),

            ProgramInstruction::FinalizeDAppBookUpdate { update } => {
                dapp_book_update_handler::finalize(program_id, &accounts, &update)
            }

            ProgramInstruction::InitAddressBookUpdate {
                fee_amount,
                fee_account_guid_hash,
                update,
            } => address_book_update_handler::init(
                program_id,
                accounts,
                fee_amount,
                fee_account_guid_hash,
                &update,
            ),

            ProgramInstruction::FinalizeAddressBookUpdate { update } => {
                address_book_update_handler::finalize(program_id, accounts, &update)
            }

            ProgramInstruction::Migrate {} => migrate_handler::handle(program_id, accounts),
            ProgramInstruction::Cleanup {} => cleanup_handler::handle(program_id, accounts),

            ProgramInstruction::InitBalanceAccountAddressWhitelistUpdate {
                fee_amount,
                fee_account_guid_hash,
                account_guid_hash,
                update,
            } => balance_account_address_whitelist_update_handler::init(
                program_id,
                accounts,
                fee_amount,
                fee_account_guid_hash,
                &account_guid_hash,
                &update,
            ),

            ProgramInstruction::FinalizeBalanceAccountAddressWhitelistUpdate {
                account_guid_hash,
                update,
            } => balance_account_address_whitelist_update_handler::finalize(
                program_id,
                accounts,
                &account_guid_hash,
                &update,
            ),

            ProgramInstruction::InitSignData {
                fee_amount,
                fee_account_guid_hash,
                ref data,
            } => sign_data_handler::init(
                program_id,
                accounts,
                fee_amount,
                fee_account_guid_hash,
                data,
            ),

            ProgramInstruction::FinalizeSignData { ref data } => {
                sign_data_handler::finalize(program_id, accounts, data)
            }
        }
    }
}
