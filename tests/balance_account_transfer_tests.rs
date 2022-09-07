#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use std::borrow::BorrowMut;
use std::option::Option::None;

use solana_program::hash::Hash;
use solana_program::instruction::InstructionError::Custom;
use solana_program::system_program;
use solana_sdk::signature::Keypair;
use solana_sdk::transaction::TransactionError;

use common::instructions::finalize_transfer;
use strike_wallet::error::WalletError;
use strike_wallet::model::address_book::AddressBookEntryNameHash;
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, BooleanSetting, OperationDisposition,
};
use strike_wallet::utils::SlotId;
use {
    solana_program::system_instruction,
    solana_program_test::tokio,
    solana_sdk::{signature::Signer as SdkSigner, transaction::Transaction},
};

#[tokio::test]
async fn test_transfer_sol() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());

    let rent = context
        .test_context
        .pt_context
        .banks_client
        .get_rent()
        .await
        .unwrap();
    let balance_account_rent = rent.minimum_balance(0);
    let multisig_op_account = setup_transfer_test(
        context.borrow_mut(),
        initiator,
        &balance_account,
        None,
        balance_account_rent,
    )
    .await
    .unwrap();

    approve_or_deny_n_of_n_multisig_op(
        context.test_context.pt_context.banks_client.borrow_mut(),
        &context.test_context.program_id,
        &multisig_op_account,
        vec![&context.approvers[0], &context.approvers[1]],
        &context.test_context.pt_context.payer,
        context.test_context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // transfer enough balance from fee payer to source account
    // need at least 2x the balance account minimum
    context
        .test_context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &context.test_context.pt_context.payer.pubkey(),
                &balance_account,
                balance_account_rent * 2,
            )],
            Some(&context.test_context.pt_context.payer.pubkey()),
            &[&context.test_context.pt_context.payer],
            context.test_context.pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .get_balance(balance_account)
            .await
            .unwrap(),
        balance_account_rent * 2
    );
    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .get_balance(context.destination.pubkey())
            .await
            .unwrap(),
        0
    );

    context
        .test_context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[finalize_transfer(
                &context.test_context.program_id,
                &multisig_op_account,
                &context.wallet_account.pubkey(),
                &balance_account,
                &context.destination.pubkey(),
                &context.test_context.pt_context.payer.pubkey(),
                context.balance_account_guid_hash,
                balance_account_rent,
                &system_program::id(),
                None,
                None,
            )],
            Some(&context.test_context.pt_context.payer.pubkey()),
            &[&context.test_context.pt_context.payer],
            context.test_context.pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .get_balance(balance_account)
            .await
            .unwrap(),
        balance_account_rent
    );
    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .get_balance(context.destination.pubkey())
            .await
            .unwrap(),
        balance_account_rent
    );
}

#[tokio::test]
async fn test_transfer_sol_denied() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());

    let rent = context
        .test_context
        .pt_context
        .banks_client
        .get_rent()
        .await
        .unwrap();
    let balance_account_rent = rent.minimum_balance(0);
    let multisig_op_account = setup_transfer_test(
        context.borrow_mut(),
        &initiator,
        &balance_account,
        None,
        balance_account_rent,
    )
    .await
    .unwrap();

    approve_or_deny_n_of_n_multisig_op(
        context.test_context.pt_context.banks_client.borrow_mut(),
        &context.test_context.program_id,
        &multisig_op_account,
        vec![&context.approvers[0], &context.approvers[1]],
        &context.test_context.pt_context.payer,
        context.test_context.pt_context.last_blockhash,
        ApprovalDisposition::DENY,
        OperationDisposition::DENIED,
    )
    .await;

    // transfer enough balance from fee payer to source account
    context
        .test_context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &context.test_context.pt_context.payer.pubkey(),
                &balance_account,
                balance_account_rent * 2,
            )],
            Some(&context.test_context.pt_context.payer.pubkey()),
            &[&context.test_context.pt_context.payer],
            context.test_context.pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .get_balance(balance_account)
            .await
            .unwrap(),
        balance_account_rent * 2
    );
    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .get_balance(context.destination.pubkey())
            .await
            .unwrap(),
        0
    );

    context
        .test_context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[finalize_transfer(
                &context.test_context.program_id,
                &multisig_op_account,
                &context.wallet_account.pubkey(),
                &balance_account,
                &context.destination.pubkey(),
                &context.test_context.pt_context.payer.pubkey(),
                context.balance_account_guid_hash,
                balance_account_rent,
                &system_program::id(),
                None,
                None,
            )],
            Some(&context.test_context.pt_context.payer.pubkey()),
            &[&context.test_context.pt_context.payer],
            context.test_context.pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    // balances should all be the same
    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .get_balance(balance_account)
            .await
            .unwrap(),
        balance_account_rent * 2
    );
    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .get_balance(context.destination.pubkey())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn test_transfer_wrong_destination_name_hash() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());

    account_settings_update(
        &mut context,
        Some(BooleanSetting::On),
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    let destination_to_add = context.allowed_destination;
    modify_balance_account_address_whitelist(
        &mut context,
        vec![(SlotId::new(0), destination_to_add)],
        None,
    )
    .await;

    context.destination_name_hash = AddressBookEntryNameHash::zero();

    assert_eq!(
        setup_transfer_test(
            context.borrow_mut(),
            &initiator,
            &balance_account,
            None,
            123,
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(1, Custom(WalletError::DestinationNotAllowed as u32)),
    )
}

#[tokio::test]
async fn test_transfer_requires_multisig() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());
    let multisig_op_account = setup_transfer_test(
        context.borrow_mut(),
        &initiator,
        &balance_account,
        None,
        123,
    )
    .await
    .unwrap();

    approve_or_deny_1_of_2_multisig_op(
        context.test_context.pt_context.banks_client.borrow_mut(),
        &context.test_context.program_id,
        &multisig_op_account,
        &context.approvers[0],
        &context.test_context.pt_context.payer,
        &context.approvers[1].pubkey(),
        context.test_context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
    )
    .await;

    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[finalize_transfer(
                    &context.test_context.program_id,
                    &multisig_op_account,
                    &context.wallet_account.pubkey(),
                    &balance_account,
                    &context.destination.pubkey(),
                    &context.test_context.pt_context.payer.pubkey(),
                    context.balance_account_guid_hash,
                    123,
                    &system_program::id(),
                    None,
                    None,
                )],
                Some(&context.test_context.pt_context.payer.pubkey()),
                &[&context.test_context.pt_context.payer],
                context.test_context.pt_context.last_blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(
            0,
            Custom(WalletError::TransferDispositionNotFinal as u32)
        ),
    );
}

#[tokio::test]
async fn test_approval_fails_if_incorrect_params_hash() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());
    let multisig_op_account = setup_transfer_test(
        context.borrow_mut(),
        &initiator,
        &balance_account,
        None,
        123,
    )
    .await
    .unwrap();

    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[set_approval_disposition(
                    &context.test_context.program_id,
                    &multisig_op_account,
                    &context.approvers[1].pubkey(),
                    ApprovalDisposition::APPROVE,
                    Hash::new_from_array([0; 32])
                )],
                Some(&context.test_context.pt_context.payer.pubkey()),
                &[
                    &context.test_context.pt_context.payer,
                    &context.approvers[1]
                ],
                context.test_context.pt_context.last_blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::InvalidSignature as u32)),
    );
}

#[tokio::test]
async fn test_transfer_insufficient_balance() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());

    let rent = context
        .test_context
        .pt_context
        .banks_client
        .get_rent()
        .await
        .unwrap();
    let balance_account_rent = rent.minimum_balance(0);

    let multisig_op_account = setup_transfer_test(
        context.borrow_mut(),
        &initiator,
        &balance_account,
        None,
        123,
    )
    .await
    .unwrap();

    approve_or_deny_n_of_n_multisig_op(
        context.test_context.pt_context.banks_client.borrow_mut(),
        &context.test_context.program_id,
        &multisig_op_account,
        vec![&context.approvers[0], &context.approvers[1]],
        &context.test_context.pt_context.payer,
        context.test_context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // can't go to zero
    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[finalize_transfer(
                    &context.test_context.program_id,
                    &multisig_op_account,
                    &context.wallet_account.pubkey(),
                    &balance_account,
                    &context.destination.pubkey(),
                    &context.test_context.pt_context.payer.pubkey(),
                    context.balance_account_guid_hash,
                    123,
                    &system_program::id(),
                    None,
                    None,
                )],
                Some(&context.test_context.pt_context.payer.pubkey()),
                &[&context.test_context.pt_context.payer],
                context.test_context.pt_context.last_blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::InsufficientBalance as u32)),
    );

    // fund balance account with amount that does not cover the transfer amount + rent exempt amount that has to remain
    context
        .test_context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &context.test_context.pt_context.payer.pubkey(),
                &balance_account,
                balance_account_rent + 122,
            )],
            Some(&context.test_context.pt_context.payer.pubkey()),
            &[&context.test_context.pt_context.payer],
            context.test_context.pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    assert_eq!(
        context
            .test_context
            .pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[finalize_transfer(
                    &context.test_context.program_id,
                    &multisig_op_account,
                    &context.wallet_account.pubkey(),
                    &balance_account,
                    &context.destination.pubkey(),
                    &context.test_context.pt_context.payer.pubkey(),
                    context.balance_account_guid_hash,
                    123,
                    &system_program::id(),
                    None,
                    None,
                )],
                Some(&context.test_context.pt_context.payer.pubkey()),
                &[&context.test_context.pt_context.payer],
                context.test_context.pt_context.last_blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::InsufficientBalance as u32)),
    );
}

#[tokio::test]
async fn test_transfer_unwhitelisted_address() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());
    account_settings_update(
        &mut context,
        Some(BooleanSetting::On),
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    assert_eq!(
        setup_transfer_test(
            context.borrow_mut(),
            &initiator,
            &balance_account,
            None,
            123,
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(1, Custom(WalletError::DestinationNotAllowed as u32)),
    );
}

#[tokio::test]
async fn test_transfer_initiator_approval() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());

    let multisig_op_account =
        setup_transfer_test(context.borrow_mut(), initiator, &balance_account, None, 123)
            .await
            .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(
            &mut context.test_context.pt_context.banks_client,
            multisig_op_account,
        )
        .await,
        2,
        &vec![
            ApprovalDispositionRecord {
                approver: context.approvers[0].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
            ApprovalDispositionRecord {
                approver: context.approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ],
        OperationDisposition::NONE,
    );

    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;
    let initiator = &Keypair::from_base58_string(&context.approvers[0].to_base58_string());

    let multisig_op_account =
        setup_transfer_test(context.borrow_mut(), initiator, &balance_account, None, 123)
            .await
            .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(
            &mut context.test_context.pt_context.banks_client,
            multisig_op_account,
        )
        .await,
        2,
        &vec![
            ApprovalDispositionRecord {
                approver: context.approvers[0].pubkey(),
                disposition: ApprovalDisposition::APPROVE,
            },
            ApprovalDispositionRecord {
                approver: context.approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ],
        OperationDisposition::NONE,
    );
}

#[tokio::test]
async fn test_init_transfer_advances_latest_activity_timestamp() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;

    let wallet = get_wallet(
        &mut context.test_context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;

    context
        .test_context
        .pt_context
        .warp_to_slot(100_000)
        .unwrap();

    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());
    common::utils::init_transfer(context.borrow_mut(), initiator, &balance_account, None, 123)
        .await
        .unwrap();

    assert!(
        get_wallet_latest_activity_timestamp(
            &mut context.test_context.pt_context.banks_client,
            &context.wallet_account.pubkey(),
        )
        .await
            > wallet.latest_activity_at
    );
}
