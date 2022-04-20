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
    next_wallet_account_info(accounts_iter, program_id)?;
    let cleanup_account_info = next_program_account_info(accounts_iter, program_id)?;
    let rent_return_account_info = next_account_info(accounts_iter)?;

    if Wallet::get_is_initialized(&cleanup_account_info.data.borrow()) {
        let cleanup_version = Wallet::version_from_slice(&cleanup_account_info.data.borrow())?;
        if cleanup_version == VERSION {
            return Err(WalletError::AccountVersionMismatch.into());
        }
        let rent_return = Wallet::get_rent_return(&cleanup_account_info.data.borrow())?;
        if *rent_return_account_info.key != rent_return {
            return Err(WalletError::AccountNotRecognized.into());
        }
    } else {
        return Err(ProgramError::UninitializedAccount);
    };

    collect_remaining_balance(cleanup_account_info, rent_return_account_info)?;

    Ok(())
}
