use crate::handlers::utils::{
    finalize_multisig_op, get_clock_from_next_account, next_program_account_info,
    next_signer_account_info, next_wallet_account_info, start_multisig_config_op,
    FeeCollectionInfo,
};
use crate::instruction::BalanceAccountPolicyUpdate;
use crate::model::balance_account::BalanceAccountGuidHash;
use crate::model::multisig_op::MultisigOpParams;
use crate::model::wallet::Wallet;
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_pack::Pack;
use solana_program::pubkey::Pubkey;

pub fn init(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    fee_amount: u64,
    fee_account_guid_hash: Option<BalanceAccountGuidHash>,
    account_guid_hash: &BalanceAccountGuidHash,
    update: &BalanceAccountPolicyUpdate,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let multisig_op_account_info = next_program_account_info(accounts_iter, program_id)?;
    let wallet_account_info = next_wallet_account_info(accounts_iter, program_id)?;
    let initiator_account_info = next_account_info(accounts_iter)?;
    let clock = get_clock_from_next_account(accounts_iter)?;
    let rent_return_account_info = next_signer_account_info(accounts_iter)?;

    let wallet = Wallet::unpack(&wallet_account_info.data.borrow())?;
    wallet.validate_config_initiator(initiator_account_info)?;
    wallet.validate_balance_account_policy_update(account_guid_hash, update)?;

    start_multisig_config_op(
        &multisig_op_account_info,
        &wallet,
        clock,
        MultisigOpParams::UpdateBalanceAccountPolicy {
            wallet_address: *wallet_account_info.key,
            account_guid_hash: *account_guid_hash,
            update: update.clone(),
        },
        *initiator_account_info.key,
        *rent_return_account_info.key,
        fee_amount,
        fee_account_guid_hash,
    )?;

    Ok(())
}

pub fn finalize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    account_guid_hash: &BalanceAccountGuidHash,
    update: &BalanceAccountPolicyUpdate,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let multisig_op_account_info = next_program_account_info(accounts_iter, program_id)?;
    let wallet_account_info = next_wallet_account_info(accounts_iter, program_id)?;
    let rent_return_account_info = next_signer_account_info(accounts_iter)?;
    let clock = get_clock_from_next_account(accounts_iter)?;
    let fee_account_info_maybe = accounts_iter.next();

    let wallet_guid_hash =
        &Wallet::wallet_guid_hash_from_slice(&wallet_account_info.data.borrow())?;

    finalize_multisig_op(
        &multisig_op_account_info,
        FeeCollectionInfo {
            rent_return_account_info,
            fee_account_info_maybe,
            wallet_guid_hash,
            program_id,
        },
        clock,
        MultisigOpParams::UpdateBalanceAccountPolicy {
            account_guid_hash: *account_guid_hash,
            wallet_address: *wallet_account_info.key,
            update: update.clone(),
        },
        || -> ProgramResult {
            let mut wallet = Wallet::unpack(&wallet_account_info.data.borrow_mut())?;
            wallet.update_balance_account_policy(account_guid_hash, update)?;
            Wallet::pack(wallet, &mut wallet_account_info.data.borrow_mut())?;
            Ok(())
        },
    )?;

    Ok(())
}
