#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use std::borrow::{Borrow, BorrowMut};
use std::time::Duration;

use solana_program::instruction::InstructionError::{Custom, MissingRequiredSignature};
use solana_sdk::transaction::TransactionError;

use crate::common::utils;
use common::instructions::finalize_balance_account_creation;
use solana_program::hash::Hash;
use solana_program::program_pack::Pack;
use solana_sdk::account::{AccountSharedData, ReadableAccount, WritableAccount};
use std::collections::HashSet;
use strike_wallet::error::WalletError;
use strike_wallet::instruction::{BalanceAccountCreation, InitialWalletConfig};
use strike_wallet::model::balance_account::{BalanceAccountGuidHash, BalanceAccountNameHash};
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, BooleanSetting, MultisigOp,
    OperationDisposition,
};
use strike_wallet::model::wallet::Wallet;
use strike_wallet::utils::SlotId;
use uuid::Uuid;
use {
    solana_program_test::tokio,
    solana_sdk::{
        pubkey::Pubkey,
        signature::{Keypair, Signer as SdkSigner},
        transaction::Transaction,
    },
};

#[tokio::test]
async fn test_balance_account_creation() {
    let mut context = setup_balance_account_tests(None, false).await;

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &context.multisig_op_account.pubkey(),
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // finalize
    let starting_rent_collector_balance = context
        .pt_context
        .banks_client
        .get_balance(context.pt_context.payer.pubkey())
        .await
        .unwrap();
    let op_account_balance = context
        .pt_context
        .banks_client
        .get_balance(context.multisig_op_account.pubkey())
        .await
        .unwrap();
    utils::finalize_balance_account_creation(context.borrow_mut()).await;

    // verify that it was created as expected
    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;

    let balance_account = wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();

    assert_eq!(balance_account.guid_hash, context.balance_account_guid_hash);
    assert_eq!(balance_account.name_hash, context.balance_account_name_hash);
    assert_eq!(
        wallet
            .get_transfer_approvers_keys(&balance_account)
            .to_set(),
        HashSet::from([context.approvers[0].pubkey(), context.approvers[1].pubkey()])
    );
    assert_eq!(
        wallet.get_allowed_destinations(&balance_account).to_set(),
        HashSet::from([])
    );
    assert_eq!(balance_account.approvals_required_for_transfer, 2);
    assert_eq!(
        balance_account.approval_timeout_for_transfer,
        Duration::from_secs(120)
    );
    assert_eq!(balance_account.whitelist_enabled, BooleanSetting::Off);
    assert_eq!(balance_account.dapps_enabled, BooleanSetting::Off);

    let expected_address_book = vec![context.balance_account_address_book_entry.clone()];
    verify_address_book(&mut context, expected_address_book, vec![]).await;

    // verify the multisig op account is closed
    assert!(context
        .pt_context
        .banks_client
        .get_account(context.multisig_op_account.pubkey())
        .await
        .unwrap()
        .is_none());
    // and that the remaining balance went to the rent collector (less the 5000 in signature fees for the finalize)
    let ending_rent_collector_balance = context
        .pt_context
        .banks_client
        .get_balance(context.pt_context.payer.pubkey())
        .await
        .unwrap();
    assert_eq!(
        starting_rent_collector_balance + op_account_balance - 5000,
        ending_rent_collector_balance
    );
}

#[tokio::test]
async fn test_balance_account_creation_fails_if_timeout_invalid() {
    let invalid_timeout_secs = vec![
        Wallet::MIN_APPROVAL_TIMEOUT.as_secs() - 1,
        Wallet::MAX_APPROVAL_TIMEOUT.as_secs() + 1,
    ];
    for secs in invalid_timeout_secs.iter() {
        let invalid_timeout = Duration::from_secs(*secs);
        assert_eq!(
            utils::setup_create_balance_account_failure_tests(
                None,
                1,
                invalid_timeout,
                vec![Pubkey::new_unique()]
            )
            .await,
            TransactionError::InstructionError(
                1,
                Custom(WalletError::InvalidApprovalTimeout as u32)
            ),
        )
    }
}

#[tokio::test]
async fn test_balance_account_creation_fails_if_no_approvers() {
    assert_eq!(
        setup_create_balance_account_failure_tests(None, 1, Duration::from_secs(18000), vec![])
            .await,
        TransactionError::InstructionError(1, Custom(WalletError::InvalidApproverCount as u32))
    )
}

#[tokio::test]
async fn test_balance_account_creation_fails_if_num_approvals_required_not_set() {
    assert_eq!(
        setup_create_balance_account_failure_tests(
            None,
            0,
            Duration::from_secs(18000),
            vec![Pubkey::new_unique()]
        )
        .await,
        TransactionError::InstructionError(1, Custom(WalletError::InvalidApproverCount as u32))
    )
}

#[tokio::test]
async fn test_balance_account_creation_not_signed_by_rent_collector() {
    let mut context = setup_balance_account_tests(None, false).await;

    // first check if it's not signed
    let rent_collector = Keypair::new();
    let mut instruction = finalize_balance_account_creation(
        &context.program_id,
        &context.wallet_account.pubkey(),
        &context.multisig_op_account.pubkey(),
        &rent_collector.pubkey(),
        context.balance_account_guid_hash,
        context.expected_creation_params,
        None,
    );
    instruction.accounts[2].is_signer = false;

    let finalize_transaction = Transaction::new_signed_with_payer(
        &[instruction.clone()],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );
    assert_eq!(
        context
            .pt_context
            .banks_client
            .process_transaction(finalize_transaction)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, MissingRequiredSignature),
    );

    // then check if it's signed but is the wrong key
    instruction.accounts[2].is_signer = true;
    let finalize_transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer, &rent_collector],
        context.pt_context.last_blockhash,
    );
    assert_eq!(
        context
            .pt_context
            .banks_client
            .process_transaction(finalize_transaction)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(
            0,
            Custom(WalletError::IncorrectRentReturnAccount as u32)
        ),
    );
}

#[tokio::test]
async fn test_balance_account_creation_incorrect_hash() {
    let mut context = setup_balance_account_tests(None, false).await;

    let wrong_guid_hash = BalanceAccountGuidHash::zero();

    let finalize_transaction_wrong_wallet_guid_hash = Transaction::new_signed_with_payer(
        &[finalize_balance_account_creation(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &context.multisig_op_account.pubkey(),
            &context.pt_context.payer.pubkey(),
            wrong_guid_hash,
            context.expected_creation_params.clone(),
            None,
        )],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );
    assert_eq!(
        context
            .pt_context
            .banks_client
            .process_transaction(finalize_transaction_wrong_wallet_guid_hash)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::InvalidSignature as u32)),
    );

    let altered_creation_params = context.expected_creation_params.borrow_mut();
    altered_creation_params.approvals_required_for_transfer = 0;

    let finalize_transaction_wrong_update = Transaction::new_signed_with_payer(
        &[finalize_balance_account_creation(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &context.multisig_op_account.pubkey(),
            &context.pt_context.payer.pubkey(),
            context.balance_account_guid_hash,
            altered_creation_params.clone(),
            None,
        )],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );

    assert_eq!(
        context
            .pt_context
            .banks_client
            .process_transaction(finalize_transaction_wrong_update)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::InvalidSignature as u32)),
    );
}

#[tokio::test]
async fn test_balance_account_creation_initiator_approval() {
    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];

    let mut context = setup_wallet_test(
        30_000,
        InitialWalletConfig {
            approvals_required_for_config: 2,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers: vec![
                (SlotId::new(0), approvers[0].pubkey_as_signer()),
                (SlotId::new(1), approvers[1].pubkey_as_signer()),
                (SlotId::new(2), approvers[2].pubkey_as_signer()),
            ],
            config_approvers: vec![SlotId::new(0), SlotId::new(1)],
        },
    )
    .await;

    let multisig_op_account = init_balance_account_creation(
        &mut context,
        &approvers[2],
        BalanceAccountGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
        BalanceAccountCreation {
            slot_id: SlotId::new(0),
            name_hash: BalanceAccountNameHash::new(&hash_of(b"Account Name")),
            approvals_required_for_transfer: 1,
            approval_timeout_for_transfer: Duration::from_secs(120),
            transfer_approvers: vec![SlotId::new(0)],
            signers_hash: hash_signers(&vec![approvers[0].pubkey_as_signer()]),
            whitelist_enabled: BooleanSetting::Off,
            dapps_enabled: BooleanSetting::Off,
            address_book_slot_id: SlotId::new(32),
        },
    )
    .await
    .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(&mut context.banks_client, multisig_op_account).await,
        2,
        &vec![
            ApprovalDispositionRecord {
                approver: approvers[0].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
            ApprovalDispositionRecord {
                approver: approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ],
        OperationDisposition::NONE,
    );

    let multisig_op_account = init_balance_account_creation(
        &mut context,
        &approvers[0],
        BalanceAccountGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
        BalanceAccountCreation {
            slot_id: SlotId::new(0),
            name_hash: BalanceAccountNameHash::new(&hash_of(b"Account Name")),
            approvals_required_for_transfer: 1,
            approval_timeout_for_transfer: Duration::from_secs(120),
            transfer_approvers: vec![SlotId::new(0)],
            signers_hash: hash_signers(&vec![approvers[0].pubkey_as_signer()]),
            whitelist_enabled: BooleanSetting::Off,
            dapps_enabled: BooleanSetting::Off,
            address_book_slot_id: SlotId::new(32),
        },
    )
    .await
    .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(&mut context.banks_client, multisig_op_account).await,
        2,
        &vec![
            ApprovalDispositionRecord {
                approver: approvers[0].pubkey(),
                disposition: ApprovalDisposition::APPROVE,
            },
            ApprovalDispositionRecord {
                approver: approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ],
        OperationDisposition::NONE,
    );
}

#[tokio::test]
async fn test_multisig_op_version_mismatch() {
    let mut context = setup_balance_account_tests(None, false).await;

    // modify the version in the multisig op
    let mut multisig_op_account_shared_data = AccountSharedData::from(
        context
            .pt_context
            .banks_client
            .get_account(context.multisig_op_account.pubkey())
            .await
            .unwrap()
            .unwrap(),
    );
    let mut multisig_op =
        MultisigOp::unpack_from_slice(multisig_op_account_shared_data.data()).unwrap();
    let correct_version = multisig_op.version;
    let bad_version = correct_version + 1;
    multisig_op.version = bad_version;
    multisig_op.pack_into_slice(multisig_op_account_shared_data.data_as_mut_slice());
    context.pt_context.set_account(
        &context.multisig_op_account.pubkey(),
        &multisig_op_account_shared_data,
    );

    // attempt to approve the config change should fail
    let approver = context.approvers[0].borrow();
    assert_eq!(
        context
            .pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[set_approval_disposition(
                    &context.program_id,
                    &context.multisig_op_account.pubkey(),
                    &approver.pubkey(),
                    ApprovalDisposition::APPROVE,
                    Hash::new_from_array([0; 32]), // doesn't matter, it will fail for version mismatch first
                )],
                Some(&context.pt_context.payer.pubkey()),
                &[&context.pt_context.payer, approver],
                context.pt_context.last_blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::OperationVersionMismatch as u32))
    );

    // put the version back and approve
    multisig_op.version = correct_version;
    multisig_op.pack_into_slice(multisig_op_account_shared_data.data_as_mut_slice());
    context.pt_context.set_account(
        &context.multisig_op_account.pubkey(),
        &multisig_op_account_shared_data,
    );

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &context.multisig_op_account.pubkey(),
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // modify the version; need to re-read multisig op state since it's changed
    let mut multisig_op_account_shared_data = AccountSharedData::from(
        context
            .pt_context
            .banks_client
            .get_account(context.multisig_op_account.pubkey())
            .await
            .unwrap()
            .unwrap(),
    );
    let mut multisig_op =
        MultisigOp::unpack_from_slice(multisig_op_account_shared_data.data()).unwrap();
    multisig_op.version = bad_version;
    multisig_op.pack_into_slice(multisig_op_account_shared_data.data_as_mut_slice());
    context.pt_context.set_account(
        &context.multisig_op_account.pubkey(),
        &multisig_op_account_shared_data,
    );

    // try to finalize again; should close the multisig op without creating the account
    utils::finalize_balance_account_creation(context.borrow_mut()).await;

    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;

    assert!(wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .is_err());
}
