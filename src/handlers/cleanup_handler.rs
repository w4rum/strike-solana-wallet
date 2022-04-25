use crate::error::WalletError;
use crate::handlers::utils::{
    collect_remaining_balance, next_program_account_info, next_wallet_account_info,
};
use crate::model::wallet::Wallet;
use crate::version::{Versioned, VERSION};
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

pub fn handle(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let wallet_account_info = next_wallet_account_info(accounts_iter, program_id)?;
    let cleanup_account_info = next_program_account_info(accounts_iter, program_id)?;
    let rent_return_account_info = next_account_info(accounts_iter)?;

    if Wallet::is_initialized_from_slice(&cleanup_account_info.data.borrow()) {
        let cleanup_version = Wallet::version_from_slice(&cleanup_account_info.data.borrow())?;
        if cleanup_version == VERSION {
            return Err(WalletError::AccountVersionMismatch.into());
        }
        let rent_return = Wallet::rent_return_from_slice(&cleanup_account_info.data.borrow())?;
        if *rent_return_account_info.key != rent_return {
            return Err(WalletError::AccountNotRecognized.into());
        }
        let cleanup_wallet_guid_hash =
            Wallet::wallet_guid_hash_from_slice(&cleanup_account_info.data.borrow())?;
        let wallet_guid_hash =
            Wallet::wallet_guid_hash_from_slice(&wallet_account_info.data.borrow())?;
        if cleanup_wallet_guid_hash != wallet_guid_hash {
            return Err(WalletError::WalletGuidHashMismatch.into());
        }
    } else {
        return Err(ProgramError::UninitializedAccount);
    };

    collect_remaining_balance(cleanup_account_info, rent_return_account_info)?;

    Ok(())
}
