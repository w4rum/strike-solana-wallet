use crate::error::WalletError;
use crate::handlers::utils::next_program_account_info;
use crate::model::wallet::Wallet;
use crate::version::{Versioned, VERSION};
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::Pack;
use solana_program::pubkey::Pubkey;
use std::collections::BTreeMap;

type MigrationFunction = fn(&AccountInfo, &mut [u8], &Pubkey);

static MIGRATION_TEST_VERSION: u32 = VERSION;

// this is a test migration which goes from the current version to version 0, and
// simply copies all the data
fn migration_test(source: &AccountInfo, destination: &mut [u8], rent_return: &Pubkey) {
    let source_account = Wallet::unpack(&**source.data.borrow()).unwrap();
    let destination_account = Wallet {
        is_initialized: true,
        version: 0,
        rent_return: *rent_return,
        wallet_guid_hash: source_account.wallet_guid_hash,
        signers: source_account.signers,
        assistant: source_account.assistant,
        address_book: source_account.address_book,
        approvals_required_for_config: source_account.approvals_required_for_config,
        approval_timeout_for_config: source_account.approval_timeout_for_config,
        config_approvers: source_account.config_approvers,
        balance_accounts: source_account.balance_accounts,
        dapp_book: source_account.dapp_book,
    };
    Wallet::pack(destination_account, destination).unwrap();
}

fn migrations() -> BTreeMap<u32, MigrationFunction> {
    BTreeMap::from([(MIGRATION_TEST_VERSION, migration_test as MigrationFunction)])
}

pub fn handle(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let source_account_info = next_program_account_info(accounts_iter, program_id)?;
    let destination_account_info = next_program_account_info(accounts_iter, program_id)?;
    let rent_return_account_info = next_account_info(accounts_iter)?;

    let source_version = Wallet::version_from_slice(&source_account_info.data.borrow())?;
    if source_version == VERSION {
        return Err(WalletError::AccountVersionMismatch.into());
    }

    if Wallet::is_initialized_from_slice(&destination_account_info.data.borrow()) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    if let Some(migrator) = migrations().get(&source_version) {
        migrator(
            source_account_info,
            &mut destination_account_info.data.borrow_mut(),
            rent_return_account_info.key,
        );
        Ok(())
    } else {
        Err(WalletError::UnknownVersion.into())
    }
}
