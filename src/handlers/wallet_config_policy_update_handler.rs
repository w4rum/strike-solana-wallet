use crate::handlers::utils::{
    calculate_expires, collect_remaining_balance, get_clock_from_next_account,
    next_program_account_info,
};
use crate::instruction::WalletConfigPolicyUpdate;
use crate::model::multisig_op::{MultisigOp, MultisigOpParams};
use crate::model::wallet::Wallet;
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::Pack;
use solana_program::pubkey::Pubkey;

pub fn init(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    update: &WalletConfigPolicyUpdate,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let multisig_op_account_info = next_program_account_info(accounts_iter, program_id)?;
    let wallet_account_info = next_program_account_info(accounts_iter, program_id)?;
    let initiator_account_info = next_account_info(accounts_iter)?;
    let clock = get_clock_from_next_account(accounts_iter)?;

    let mut wallet = Wallet::unpack(&wallet_account_info.data.borrow())?;

    wallet.validate_config_initiator(initiator_account_info)?;
    wallet.lock_config_policy_updates()?;
    wallet.validate_config_policy_update(update)?;

    let mut multisig_op = MultisigOp::unpack_unchecked(&multisig_op_account_info.data.borrow())?;

    multisig_op.init(
        wallet.get_config_approvers_keys(),
        wallet.approvals_required_for_config,
        clock.unix_timestamp,
        calculate_expires(clock.unix_timestamp, wallet.approval_timeout_for_config)?,
        MultisigOpParams::UpdateWalletConfigPolicy {
            wallet_address: *wallet_account_info.key,
            update: update.clone(),
        },
    )?;
    MultisigOp::pack(multisig_op, &mut multisig_op_account_info.data.borrow_mut())?;

    Wallet::pack(wallet, &mut wallet_account_info.data.borrow_mut())?;

    Ok(())
}

pub fn finalize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    update: &WalletConfigPolicyUpdate,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let multisig_op_account_info = next_program_account_info(accounts_iter, program_id)?;
    let wallet_account_info = next_program_account_info(accounts_iter, program_id)?;
    let account_to_return_rent_to = next_account_info(accounts_iter)?;
    let clock = get_clock_from_next_account(accounts_iter)?;

    if !account_to_return_rent_to.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let multisig_op = MultisigOp::unpack(&multisig_op_account_info.data.borrow())?;

    let expected_params = MultisigOpParams::UpdateWalletConfigPolicy {
        wallet_address: *wallet_account_info.key,
        update: update.clone(),
    };

    let mut wallet = Wallet::unpack(&wallet_account_info.data.borrow_mut())?;
    if multisig_op.approved(&expected_params, &clock)? {
        wallet.update_config_policy(update)?;
    }
    wallet.unlock_config_policy_updates();
    Wallet::pack(wallet, &mut wallet_account_info.data.borrow_mut())?;

    collect_remaining_balance(&multisig_op_account_info, &account_to_return_rent_to)?;

    Ok(())
}
