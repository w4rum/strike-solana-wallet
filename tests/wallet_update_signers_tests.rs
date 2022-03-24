#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use std::borrow::BorrowMut;
use std::time::Duration;

use solana_program::instruction::InstructionError::Custom;

use crate::common::utils;
use common::instructions;
use strike_wallet::error::WalletError;
use strike_wallet::instruction::InitialWalletConfig;
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, OperationDisposition, SlotUpdateType,
};
use strike_wallet::model::wallet::Signers;
use strike_wallet::utils::SlotId;
use {
    solana_program_test::tokio,
    solana_sdk::signature::{Keypair, Signer as SdkSigner},
};

#[tokio::test]
async fn test_add_and_remove_signer() {
    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];

    let initial_config = InitialWalletConfig {
        approvals_required_for_config: 2,
        approval_timeout_for_config: Duration::from_secs(3600),
        signers: vec![
            (SlotId::new(0), approvers[0].pubkey_as_signer()),
            (SlotId::new(1), approvers[1].pubkey_as_signer()),
        ],
        config_approvers: vec![
            (SlotId::new(0), approvers[0].pubkey_as_signer()),
            (SlotId::new(1), approvers[1].pubkey_as_signer()),
        ],
    };

    let expected_signers_after_add = Signers::from_vec(vec![
        (SlotId::new(0), approvers[0].pubkey_as_signer()),
        (SlotId::new(1), approvers[1].pubkey_as_signer()),
        (SlotId::new(2), approvers[2].pubkey_as_signer()),
    ]);

    let expected_signers_after_remove = Signers::from_vec(vec![
        (SlotId::new(0), approvers[0].pubkey_as_signer()),
        (SlotId::new(1), approvers[1].pubkey_as_signer()),
    ]);

    let signer_to_add_and_remove = approvers[2].pubkey_as_signer();

    let mut context = setup_wallet_test(40_000, initial_config).await;

    update_signer(
        context.borrow_mut(),
        vec![&approvers[0], &approvers[1]],
        SlotUpdateType::SetIfEmpty,
        2,
        signer_to_add_and_remove,
        Some(expected_signers_after_add),
        None,
    )
    .await;

    update_signer(
        context.borrow_mut(),
        vec![&approvers[0], &approvers[1]],
        SlotUpdateType::Clear,
        2,
        signer_to_add_and_remove,
        Some(expected_signers_after_remove),
        None,
    )
    .await;
}

#[tokio::test]
async fn test_add_and_remove_signer_init_failures() {
    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];

    let initial_config = InitialWalletConfig {
        approvals_required_for_config: 2,
        approval_timeout_for_config: Duration::from_secs(3600),
        signers: vec![
            (SlotId::new(0), approvers[0].pubkey_as_signer()),
            (SlotId::new(1), approvers[1].pubkey_as_signer()),
        ],
        config_approvers: vec![
            (SlotId::new(0), approvers[0].pubkey_as_signer()),
            (SlotId::new(1), approvers[1].pubkey_as_signer()),
        ],
    };

    let signer1 = approvers[1].pubkey_as_signer();
    let signer2 = approvers[2].pubkey_as_signer();

    let mut context = setup_wallet_test(40_000, initial_config).await;

    // put a signer in a slot already filled
    update_signer(
        context.borrow_mut(),
        vec![&approvers[0], &approvers[1]],
        SlotUpdateType::SetIfEmpty,
        1,
        signer2,
        None,
        Some(Custom(WalletError::SlotCannotBeInserted as u32)),
    )
    .await;

    // try to remove the signer from an occupied slot but give a wrong key
    update_signer(
        context.borrow_mut(),
        vec![&approvers[0], &approvers[1]],
        SlotUpdateType::Clear,
        1,
        signer2,
        None,
        Some(Custom(WalletError::SlotCannotBeRemoved as u32)),
    )
    .await;

    // try to remove the signer that is a config approver
    update_signer(
        context.borrow_mut(),
        vec![&approvers[0], &approvers[1]],
        SlotUpdateType::Clear,
        1,
        signer1,
        None,
        Some(Custom(WalletError::SignerIsConfigApprover as u32)),
    )
    .await;
}

#[tokio::test]
async fn test_remove_signer_fails_for_a_transfer_approver() {
    let mut context = setup_balance_account_tests(None, true).await;

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
    utils::finalize_balance_account_creation(context.borrow_mut()).await;

    // approvers 0 & 1 are config and transfer approvers, 2 is just a transfer approver
    let multisig_op_account = Keypair::new();
    verify_multisig_op_init_fails(
        &mut context.pt_context.banks_client,
        context.pt_context.last_blockhash,
        &context.pt_context.payer,
        &context.assistant_account,
        &multisig_op_account,
        instructions::init_update_signer(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &multisig_op_account.pubkey(),
            &context.assistant_account.pubkey(),
            SlotUpdateType::Clear,
            SlotId::new(2),
            context.approvers[2].pubkey_as_signer(),
        ),
        Custom(WalletError::SignerIsTransferApprover as u32),
    )
    .await;
}

#[tokio::test]
async fn test_signers_update_initiator_approval() {
    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];

    let mut context = setup_wallet_test(
        30_000,
        InitialWalletConfig {
            approvals_required_for_config: 2,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers: vec![
                (SlotId::new(0), approvers[0].pubkey_as_signer()),
                (SlotId::new(1), approvers[1].pubkey_as_signer()),
            ],
            config_approvers: vec![
                (SlotId::new(0), approvers[0].pubkey_as_signer()),
                (SlotId::new(1), approvers[1].pubkey_as_signer()),
            ],
        },
    )
    .await;

    let signer_to_add_and_remove = approvers[2].pubkey_as_signer();
    let multisig_op_account = utils::init_update_signer(
        context.borrow_mut(),
        &approvers[0],
        SlotUpdateType::SetIfEmpty,
        2,
        signer_to_add_and_remove,
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

    let mut context = setup_wallet_test(
        30_000,
        InitialWalletConfig {
            approvals_required_for_config: 1,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers: vec![
                (SlotId::new(0), approvers[0].pubkey_as_signer()),
                (SlotId::new(1), approvers[1].pubkey_as_signer()),
            ],
            config_approvers: vec![
                (SlotId::new(0), approvers[0].pubkey_as_signer()),
                (SlotId::new(1), approvers[1].pubkey_as_signer()),
            ],
        },
    )
    .await;

    let signer_to_add_and_remove = approvers[2].pubkey_as_signer();
    let multisig_op_account = utils::init_update_signer(
        context.borrow_mut(),
        &approvers[0],
        SlotUpdateType::SetIfEmpty,
        2,
        signer_to_add_and_remove,
    )
    .await
    .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(&mut context.banks_client, multisig_op_account).await,
        1,
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
        OperationDisposition::APPROVED,
    );
}
