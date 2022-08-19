use std::cmp::max;
use std::slice::Iter;
use std::time::Duration;

use solana_program::rent::Rent;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
    system_instruction,
    sysvar::Sysvar,
};
use spl_associated_token_account;

use crate::error::WalletError;
use crate::model::balance_account::{BalanceAccount, BalanceAccountGuidHash};
use crate::model::multisig_op::{
    ApprovalDisposition, MultisigOp, MultisigOpParams, OperationDisposition,
};
use crate::model::wallet::{Wallet, WalletGuidHash};
use crate::version::{Versioned, VERSION};

pub struct FeeCollectionInfo<'a, 'b> {
    pub rent_return_account_info: &'a AccountInfo<'b>,
    pub fee_account_info_maybe: Option<&'a AccountInfo<'b>>,
    pub wallet_guid_hash: &'a WalletGuidHash,
    pub program_id: &'a Pubkey,
}

pub fn collect_remaining_balance(from: &AccountInfo, to: &AccountInfo) -> ProgramResult {
    // this moves the lamports back to the fee payer.
    **to.lamports.borrow_mut() = to
        .lamports()
        .checked_add(from.lamports())
        .ok_or(WalletError::AmountOverflow)?;
    **from.lamports.borrow_mut() = 0;
    *from.data.borrow_mut() = &mut [];

    Ok(())
}

pub fn next_program_account_info<'a, 'b, I: Iterator<Item = &'a AccountInfo<'b>>>(
    iter: &mut I,
    program_id: &Pubkey,
) -> Result<I::Item, ProgramError> {
    let account_info = next_account_info(iter)?;
    if account_info.owner != program_id {
        msg!("Account does not belong to the program");
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(account_info)
}

pub fn next_wallet_account_info<'a, 'b, I: Iterator<Item = &'a AccountInfo<'b>>>(
    iter: &mut I,
    program_id: &Pubkey,
) -> Result<I::Item, ProgramError> {
    let account_info = next_program_account_info(iter, program_id)?;
    if Wallet::version_from_slice(&**account_info.data.borrow())? != VERSION {
        Err(WalletError::AccountVersionMismatch.into())
    } else {
        Ok(account_info)
    }
}

pub fn get_clock_from_next_account(iter: &mut Iter<AccountInfo>) -> Result<Clock, ProgramError> {
    let account_info = next_account_info(iter)?;
    if solana_program::sysvar::clock::id() != *account_info.key {
        msg!("Invalid clock account");
        return Err(WalletError::AccountNotRecognized.into());
    }
    Clock::from_account_info(&account_info)
}

pub fn next_signer_account_info<'a, 'b, I: Iterator<Item = &'a AccountInfo<'b>>>(
    iter: &mut I,
) -> Result<I::Item, ProgramError> {
    let account_info = next_account_info(iter)?;
    if !account_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(account_info)
}

pub fn calculate_expires(start: i64, duration: Duration) -> Result<i64, ProgramError> {
    let expires_at = start.checked_add(duration.as_secs() as i64);
    if expires_at == None {
        msg!("Invalid expires_at");
        return Err(ProgramError::InvalidArgument);
    }
    Ok(expires_at.unwrap())
}

/// validate the PDA of a BalanceAccount and return its bump seed.
pub fn validate_balance_account_and_get_seed(
    balance_account_info: &AccountInfo,
    wallet_guid_hash: &WalletGuidHash,
    account_guid_hash: &BalanceAccountGuidHash,
    program_id: &Pubkey,
) -> Result<u8, ProgramError> {
    let seeds = &[wallet_guid_hash.to_bytes(), account_guid_hash.to_bytes()];
    match verify_pda(program_id, seeds, balance_account_info.key, None) {
        Ok((_pda, bump_seed)) => Ok(bump_seed),
        Err(_error) => Err(WalletError::InvalidPDA.into()),
    }
}

pub fn start_multisig_transfer_op(
    multisig_op_account_info: &AccountInfo,
    wallet: &Wallet,
    balance_account: &BalanceAccount,
    clock: Clock,
    params: MultisigOpParams,
    initiator: Pubkey,
    rent_return: Pubkey,
    fee_amount: u64,
    fee_account_guid_hash: Option<BalanceAccountGuidHash>,
) -> ProgramResult {
    let mut multisig_op = MultisigOp::unpack_unchecked(&multisig_op_account_info.data.borrow())?;

    multisig_op.init(
        wallet.wallet_guid_hash,
        Some(balance_account.guid_hash),
        wallet.get_transfer_approvers_keys(balance_account),
        (initiator, ApprovalDisposition::APPROVE),
        balance_account.approvals_required_for_transfer,
        clock.unix_timestamp,
        calculate_expires(
            clock.unix_timestamp,
            balance_account.approval_timeout_for_transfer,
        )?,
        Some(params),
        rent_return,
        fee_amount,
        fee_account_guid_hash,
        None,
    )?;
    MultisigOp::pack(multisig_op, &mut multisig_op_account_info.data.borrow_mut())?;

    Ok(())
}

pub fn start_multisig_config_op(
    multisig_op_account_info: &AccountInfo,
    wallet: &Wallet,
    balance_account_guid_hash: Option<BalanceAccountGuidHash>,
    clock: Clock,
    params: MultisigOpParams,
    initiator: Pubkey,
    rent_return: Pubkey,
    fee_amount: u64,
    fee_account_guid_hash: Option<BalanceAccountGuidHash>,
) -> ProgramResult {
    let mut multisig_op = MultisigOp::unpack_unchecked(&multisig_op_account_info.data.borrow())?;

    multisig_op.init(
        wallet.wallet_guid_hash,
        balance_account_guid_hash,
        wallet.get_config_approvers_keys(),
        (initiator, ApprovalDisposition::APPROVE),
        wallet.approvals_required_for_config,
        clock.unix_timestamp,
        calculate_expires(clock.unix_timestamp, wallet.approval_timeout_for_config)?,
        Some(params),
        rent_return,
        fee_amount,
        fee_account_guid_hash,
        None,
    )?;
    MultisigOp::pack(multisig_op, &mut multisig_op_account_info.data.borrow_mut())?;

    Ok(())
}

pub fn log_op_disposition(disposition: OperationDisposition) {
    msg!("OperationDisposition: [{}]", disposition.to_u8());
}

pub fn finalize_multisig_op<'a, F, G>(
    multisig_op_account_info: &AccountInfo,
    fee_collection_info: FeeCollectionInfo,
    clock: Clock,
    expected_params: MultisigOpParams,
    mut on_op_approved: F,
    mut on_op_not_approved: G,
) -> ProgramResult
where
    F: FnMut() -> ProgramResult,
    G: FnMut() -> ProgramResult,
{
    if MultisigOp::version_from_slice(&multisig_op_account_info.data.borrow())? == VERSION {
        let multisig_op = MultisigOp::unpack(&multisig_op_account_info.data.borrow())?;

        if *fee_collection_info.rent_return_account_info.key != multisig_op.rent_return {
            return Err(WalletError::IncorrectRentReturnAccount.into());
        }

        if multisig_op.approved(expected_params.hash(&multisig_op), &clock)? {
            on_op_approved()?;
        } else {
            on_op_not_approved()?;
        }

        if multisig_op.fee_amount > 0 {
            // attempt to collect fees
            if let Some(guid_hash) = multisig_op.fee_account_guid_hash {
                if let Some(fee_account_info) = fee_collection_info.fee_account_info_maybe {
                    let fee_collection = || -> Result<(), ProgramError> {
                        let bump_seed = validate_balance_account_and_get_seed(
                            fee_account_info,
                            fee_collection_info.wallet_guid_hash,
                            &guid_hash,
                            fee_collection_info.program_id,
                        )?;
                        // this will transfer as much of the fee as possible without taking the
                        // fee account below the minimum balance
                        let rent = Rent::get()?;
                        let balance_floor = rent.minimum_balance(0);
                        let final_from_lamports = max(
                            balance_floor,
                            fee_account_info
                                .lamports()
                                .saturating_sub(multisig_op.fee_amount),
                        );
                        let amount = fee_account_info
                            .lamports()
                            .saturating_sub(final_from_lamports);

                        invoke_signed(
                            &system_instruction::transfer(
                                fee_account_info.key,
                                fee_collection_info.rent_return_account_info.key,
                                amount,
                            ),
                            &[
                                fee_account_info.clone(),
                                fee_collection_info.rent_return_account_info.clone(),
                            ],
                            &[&[
                                fee_collection_info.wallet_guid_hash.to_bytes(),
                                guid_hash.to_bytes(),
                                &[bump_seed],
                            ]],
                        )?;
                        Ok(())
                    };
                    if let Err(err) = fee_collection() {
                        msg!("Unable to collect fees: {:?}", err);
                    }
                }
            }
        }
    } else {
        log_op_disposition(OperationDisposition::EXPIRED);
    }

    collect_remaining_balance(
        &multisig_op_account_info,
        fee_collection_info.rent_return_account_info,
    )?;

    Ok(())
}

pub fn transfer_sol_checked<'a>(
    wallet_guid_hash: &WalletGuidHash,
    balance_account: AccountInfo<'a>,
    account_guid_hash: &BalanceAccountGuidHash,
    bump_seed: u8,
    system_program_account: AccountInfo<'a>,
    to: AccountInfo<'a>,
    lamports: u64,
) -> ProgramResult {
    let balance_account_rent = Rent::get().unwrap().minimum_balance(0);
    let lamports_plus_rent = lamports
        .checked_add(balance_account_rent)
        .ok_or(WalletError::AmountOverflow)?;

    if balance_account.lamports() < lamports_plus_rent {
        msg!(
            "Account only has {} lamports of {} requested while having to keep {} lamports for rent exemption",
            balance_account.lamports(),
            lamports,
            balance_account_rent
        );
        return Err(WalletError::InsufficientBalance.into());
    }
    let instruction = &system_instruction::transfer(balance_account.key, to.key, lamports);
    invoke_signed(
        instruction,
        &[balance_account, to, system_program_account],
        &[&[
            wallet_guid_hash.to_bytes(),
            account_guid_hash.to_bytes(),
            &[bump_seed],
        ]],
    )
}

/// Validate a given PDA and optionally its corresponding bump seed. If valid,
/// the key and bump_seed are returned in the result.
pub fn verify_pda(
    program_id: &Pubkey,
    seeds: &[&[u8]],
    expected_key: &Pubkey,
    expected_bump_seed: Option<u8>,
) -> Result<(Pubkey, u8), ProgramError> {
    let (key, bump_seed) = Pubkey::find_program_address(seeds, program_id);
    if key != *expected_key {
        return Err(WalletError::InvalidPDA.into());
    }
    // verify bump seed
    if let Some(expected_bump_seed_value) = expected_bump_seed {
        if bump_seed != expected_bump_seed_value {
            return Err(WalletError::InvalidPDA.into());
        }
    }
    Ok((key, bump_seed))
}

/// Build an instruction to create an "associated token account" for the given
/// balance account.
pub fn create_associated_token_account_instruction(
    payer_account_info: &AccountInfo,
    associated_token_account_info: &AccountInfo,
    balance_account_info: &AccountInfo,
    token_mint_account_info: &AccountInfo,
) -> Instruction {
    Instruction {
        program_id: spl_associated_token_account::id(),
        accounts: vec![
            AccountMeta::new(*payer_account_info.key, true),
            AccountMeta::new(*associated_token_account_info.key, false),
            AccountMeta::new_readonly(*balance_account_info.key, false),
            AccountMeta::new_readonly(*token_mint_account_info.key, false),
            AccountMeta::new_readonly(solana_program::system_program::id(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
        data: vec![0],
    }
}
