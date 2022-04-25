use bitvec::macros::internal::funty::Fundamental;
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::hash::Hash;
use solana_program::instruction::Instruction;
use solana_program::msg;
use solana_program::program::invoke_signed;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::Pack;
use solana_program::pubkey::Pubkey;
use spl_token::state::Account as SPLAccount;

use crate::error::WalletError;
use crate::handlers::utils::{
    calculate_expires, collect_remaining_balance, get_clock_from_next_account, log_op_disposition,
    next_program_account_info, next_wallet_account_info, validate_balance_account_and_get_seed,
};
use crate::model::address_book::DAppBookEntry;
use crate::model::balance_account::BalanceAccountGuidHash;
use crate::model::dapp_multisig_data::DAppMultisigData;
use crate::model::multisig_op::{ApprovalDisposition, MultisigOp, OperationDisposition};
use crate::model::wallet::Wallet;
use crate::version::{Versioned, VERSION};

pub fn init(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    account_guid_hash: &BalanceAccountGuidHash,
    dapp: DAppBookEntry,
    instruction_count: u8,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let multisig_op_account_info = next_program_account_info(accounts_iter, program_id)?;
    let multisig_data_account_info = next_program_account_info(accounts_iter, program_id)?;
    let wallet_account_info = next_wallet_account_info(accounts_iter, program_id)?;
    let initiator_account_info = next_account_info(accounts_iter)?;
    let clock = get_clock_from_next_account(accounts_iter)?;

    let wallet = Wallet::unpack(&wallet_account_info.data.borrow())?;
    let balance_account = wallet.get_balance_account(account_guid_hash)?;

    if balance_account.are_dapps_disabled() {
        return Err(WalletError::DAppsDisabled.into());
    }

    wallet.validate_transfer_initiator(initiator_account_info)?;

    if !balance_account.is_whitelist_disabled() {
        if !wallet.dapp_allowed(dapp) {
            return Err(WalletError::DAppNotAllowed.into());
        }
    }

    let mut multisig_op = MultisigOp::unpack_unchecked(&multisig_op_account_info.data.borrow())?;
    multisig_op.init(
        wallet.get_transfer_approvers_keys(&balance_account),
        (*initiator_account_info.key, ApprovalDisposition::NONE),
        1,
        clock.unix_timestamp,
        calculate_expires(
            clock.unix_timestamp,
            balance_account.approval_timeout_for_transfer,
        )?,
        None,
    )?;
    MultisigOp::pack(multisig_op, &mut multisig_op_account_info.data.borrow_mut())?;

    let mut multisig_data =
        DAppMultisigData::unpack_unchecked(&multisig_data_account_info.data.borrow())?;
    multisig_data.init(
        *wallet_account_info.key,
        *account_guid_hash,
        dapp,
        instruction_count,
    )?;
    DAppMultisigData::pack(
        multisig_data,
        &mut multisig_data_account_info.data.borrow_mut(),
    )?;

    Ok(())
}

pub fn supply_instructions(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    starting_index: u8,
    instructions: Vec<Instruction>,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let multisig_op_account_info = next_program_account_info(accounts_iter, program_id)?;
    let multisig_data_account_info = next_program_account_info(accounts_iter, program_id)?;
    let initiator_account_info = next_account_info(accounts_iter)?;

    if !initiator_account_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if MultisigOp::version_from_slice(&multisig_op_account_info.data.borrow())? != VERSION {
        return Err(WalletError::OperationVersionMismatch.into());
    }

    // TODO - once we are storing the initiator in the multisig op (PRIME-3999), verify that the supplied one matches

    let params_hash = {
        let mut multisig_data =
            DAppMultisigData::unpack(&multisig_data_account_info.data.borrow())?;

        for index in starting_index..starting_index + instructions.len().as_u8() {
            multisig_data.add_instruction(
                index,
                &instructions
                    .get(usize::from(index - starting_index))
                    .unwrap(),
            )?;
        }

        let params_hash = if multisig_data.all_instructions_supplied() {
            Some(multisig_data.hash()?)
        } else {
            None
        };

        DAppMultisigData::pack(
            multisig_data,
            &mut multisig_data_account_info.data.borrow_mut(),
        )?;

        params_hash
    };

    // separate block so memory from unpacking the data gets reused
    if let Some(_) = params_hash {
        let mut multisig_op = MultisigOp::unpack(&multisig_op_account_info.data.borrow())?;

        multisig_op.params_hash = params_hash;

        // record approval
        if let Some(record) = multisig_op
            .disposition_records
            .iter_mut()
            .find(|r| r.approver == *initiator_account_info.key)
        {
            if record.disposition == ApprovalDisposition::NONE {
                record.disposition = ApprovalDisposition::APPROVE
            }
        }
        if multisig_op.get_disposition_count(ApprovalDisposition::APPROVE)
            == multisig_op.dispositions_required
        {
            multisig_op.operation_disposition = OperationDisposition::APPROVED
        }

        MultisigOp::pack(multisig_op, &mut multisig_op_account_info.data.borrow_mut())?;
    }

    Ok(())
}

fn account_balances(accounts: &[AccountInfo]) -> Vec<u64> {
    accounts.iter().map(|a| a.lamports()).collect()
}

fn spl_balances(accounts: &[AccountInfo]) -> Vec<SplBalance> {
    accounts
        .iter()
        .filter_map(|a| {
            if *a.owner == spl_token::id() {
                SPLAccount::unpack(&a.data.borrow())
                    .ok()
                    .map(|account_data| SplBalance {
                        account: *a.key,
                        token_mint: account_data.mint,
                        balance: account_data.amount,
                    })
            } else {
                None
            }
        })
        .collect()
}

fn balance_changes_from_simulation(
    starting_balances: Vec<u64>,
    starting_spl_balances: Vec<SplBalance>,
    ending_balances: Vec<u64>,
    ending_spl_balances: Vec<SplBalance>,
    accounts: &[AccountInfo],
) -> String {
    // compute just the changes to minimize compute budget spend
    let balance_changes: Vec<(u8, char, u64)> = starting_balances
        .into_iter()
        .enumerate()
        .filter_map(|(i, starting_balance)| {
            if ending_balances[i] > starting_balance {
                Some((i as u8, '+', ending_balances[i] - starting_balance))
            } else if ending_balances[i] < starting_balance {
                Some((i as u8, '-', starting_balance - ending_balances[i]))
            } else {
                None
            }
        })
        .collect();

    let spl_balance_changes: Vec<(u8, char, u64)> = ending_spl_balances
        .into_iter()
        .filter_map(|end| {
            let starting_balance = starting_spl_balances
                .iter()
                .find(|start| start.account == end.account && start.token_mint == end.token_mint)
                .map(|start| start.balance)
                .unwrap_or(0);
            if end.balance == starting_balance {
                None
            } else {
                let index = accounts
                    .iter()
                    .position(|a| *a.key == end.account)
                    .unwrap()
                    .as_u8();
                if end.balance > starting_balance {
                    Some((
                        index,
                        '+',
                        end.balance.checked_sub(starting_balance).unwrap(),
                    ))
                } else {
                    Some((
                        index,
                        '-',
                        starting_balance.checked_sub(end.balance).unwrap(),
                    ))
                }
            }
        })
        .collect();
    format!(
        "Simulation balance changes: {:?} {:?}",
        balance_changes, spl_balance_changes
    )
}

pub fn finalize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    account_guid_hash: &BalanceAccountGuidHash,
    params_hash: &Hash,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let multisig_op_account_info = next_program_account_info(accounts_iter, program_id)?;
    let multisig_data_account_info = next_program_account_info(accounts_iter, program_id)?;
    let wallet_account_info = next_program_account_info(accounts_iter, program_id)?;
    let balance_account = next_account_info(accounts_iter)?;
    let rent_collector_account_info = next_account_info(accounts_iter)?;
    let clock = get_clock_from_next_account(accounts_iter)?;

    if !rent_collector_account_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if MultisigOp::version_from_slice(&multisig_op_account_info.data.borrow())? == VERSION {
        let multisig_op = MultisigOp::unpack(&multisig_op_account_info.data.borrow())?;
        let multisig_data = DAppMultisigData::unpack(&multisig_data_account_info.data.borrow())?;

        let instructions = multisig_data.instructions()?;
        let (is_approved, is_final) = {
            const NOT_FINAL: u32 = WalletError::TransferDispositionNotFinal as u32;
            match multisig_op.approved(multisig_data.hash()?, &clock, Some(params_hash)) {
                Ok(a) => (a, true),
                Err(ProgramError::Custom(NOT_FINAL)) => (false, false),
                Err(e) => return Err(e),
            }
        };

        let wallet_guid_hash =
            &Wallet::wallet_guid_hash_from_slice(&wallet_account_info.data.borrow())?;

        let bump_seed = validate_balance_account_and_get_seed(
            balance_account,
            wallet_guid_hash,
            account_guid_hash,
            program_id,
        )?;

        let starting_balances: Vec<u64> = if is_final {
            Vec::new()
        } else {
            account_balances(accounts)
        };

        let starting_spl_balances: Vec<SplBalance> = if is_final {
            Vec::new()
        } else {
            spl_balances(accounts)
        };

        // actually run instructions if action is approved or this is a simulation (we are not final)
        if is_approved || !is_final {
            for instruction in instructions.iter() {
                invoke_signed(
                    &instruction,
                    &accounts,
                    &[&[
                        wallet_guid_hash.to_bytes(),
                        account_guid_hash.to_bytes(),
                        &[bump_seed],
                    ]],
                )?;
            }
        }

        if is_final {
            cleanup(
                &multisig_op_account_info,
                &multisig_data_account_info,
                &rent_collector_account_info,
            )
        } else {
            msg!(&balance_changes_from_simulation(
                starting_balances,
                starting_spl_balances,
                account_balances(accounts),
                spl_balances(accounts),
                accounts,
            ));
            Err(WalletError::SimulationFinished.into())
        }
    } else {
        log_op_disposition(OperationDisposition::EXPIRED);
        cleanup(
            &multisig_op_account_info,
            &multisig_data_account_info,
            &rent_collector_account_info,
        )
    }
}

fn cleanup(
    multisig_op_account_info: &AccountInfo,
    multisig_data_account_info: &AccountInfo,
    rent_collector_account_info: &AccountInfo,
) -> ProgramResult {
    collect_remaining_balance(multisig_op_account_info, rent_collector_account_info)?;
    collect_remaining_balance(multisig_data_account_info, rent_collector_account_info)?;

    Ok(())
}

struct SplBalance {
    account: Pubkey,
    token_mint: Pubkey,
    balance: u64,
}

#[test]
fn test_balance_changes() {
    assert_eq![
        "Simulation balance changes: [] []",
        balance_changes_from_simulation(vec![], vec![], vec![], vec![], &[])
    ];
    assert_eq![
        "Simulation balance changes: [(0, '+', 100)] []",
        balance_changes_from_simulation(vec![0], vec![], vec![100], vec![], &[])
    ];
    assert_eq![
        "Simulation balance changes: [(1, '-', 100)] []",
        balance_changes_from_simulation(vec![0, 100], vec![], vec![0, 0], vec![], &[])
    ];
    let account = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let token_mint = Pubkey::new_unique();
    let mut account_lamports = 0;
    let mut account_data: [u8; 0] = [0; 0];
    let account_info = AccountInfo::new(
        &account,
        false,
        false,
        &mut account_lamports,
        &mut account_data,
        &owner,
        false,
        0,
    );

    assert_eq![
        "Simulation balance changes: [] [(0, '+', 100)]",
        balance_changes_from_simulation(
            vec![],
            vec![SplBalance {
                account,
                token_mint,
                balance: 0
            }],
            vec![],
            vec![SplBalance {
                account,
                token_mint,
                balance: 100
            }],
            &[account_info.clone()]
        )
    ];

    let other_account = Pubkey::new_unique();
    let mut other_account_info = account_info.clone();
    other_account_info.key = &other_account;

    assert_eq![
        "Simulation balance changes: [] [(1, '-', 100)]",
        balance_changes_from_simulation(
            vec![],
            vec![SplBalance {
                account,
                token_mint,
                balance: 200
            }],
            vec![],
            vec![SplBalance {
                account,
                token_mint,
                balance: 100
            }],
            &[other_account_info.clone(), account_info.clone()]
        )
    ];

    assert_eq![
        "Simulation balance changes: [] [(0, '+', 100)]",
        balance_changes_from_simulation(
            vec![],
            vec![SplBalance {
                account: other_account,
                token_mint,
                balance: 200
            }],
            vec![],
            vec![SplBalance {
                account,
                token_mint,
                balance: 100
            }],
            &[account_info.clone(), other_account_info.clone()]
        )
    ];
}
