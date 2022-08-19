#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use std::borrow::BorrowMut;
use std::time::Duration;

use solana_program::instruction::InstructionError::Custom;

use common::instructions::{
    finalize_balance_account_policy_update_instruction,
    init_balance_account_policy_update_instruction,
};
use std::collections::HashSet;
use strike_wallet::error::WalletError;
use strike_wallet::instruction::BalanceAccountPolicyUpdate;
use strike_wallet::model::balance_account::{BalanceAccountGuidHash, BalanceAccountNameHash};
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, OperationDisposition,
};
use strike_wallet::utils::SlotId;
use {
    solana_program::system_instruction,
    solana_program_test::tokio,
    solana_sdk::{
        program_pack::Pack,
        signature::{Keypair, Signer as SdkSigner},
        transaction::Transaction,
    },
    strike_wallet::model::multisig_op::MultisigOp,
};

#[tokio::test]
async fn test_balance_account_policy_update() {
    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(200000), true).await;

    let wallet = get_wallet(
        &mut context.test_context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;
    let balance_account = wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();

    let signers_hash = hash_signers(&vec![
        context.approvers[1].pubkey_as_signer(),
        context.approvers[2].pubkey_as_signer(),
    ]);
    let update = BalanceAccountPolicyUpdate {
        approvals_required_for_transfer: 1,
        approval_timeout_for_transfer: Duration::from_secs(7200),
        transfer_approvers: vec![SlotId::new(1), SlotId::new(2)],
        signers_hash,
    };
    let multisig_op_account = update_balance_account_policy(&mut context, update, None)
        .await
        .unwrap();

    // verify that it was updated as expected
    let updated_wallet = get_wallet(
        &mut context.test_context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;
    let updated_balance_account = updated_wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();

    assert_eq!(
        updated_balance_account.guid_hash,
        context.balance_account_guid_hash
    );
    assert_eq!(updated_balance_account.approvals_required_for_transfer, 1);
    assert_eq!(
        updated_balance_account.approval_timeout_for_transfer,
        Duration::from_secs(7200)
    );
    assert_eq!(updated_balance_account.name_hash, balance_account.name_hash);
    assert_eq!(
        updated_wallet
            .get_transfer_approvers_keys(&updated_balance_account)
            .to_set(),
        HashSet::from([context.approvers[1].pubkey(), context.approvers[2].pubkey()])
    );
    assert_eq!(
        updated_wallet
            .get_allowed_destinations(&updated_balance_account)
            .to_set(),
        wallet.get_allowed_destinations(&balance_account).to_set(),
    );

    // verify the multisig op account is closed
    assert!(context
        .test_context
        .pt_context
        .banks_client
        .get_account(multisig_op_account)
        .await
        .unwrap()
        .is_none());

    // verify changing time updates
    let mut expected_balance_account = get_wallet(
        &mut context.test_context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await
    .get_balance_account(&context.balance_account_guid_hash)
    .unwrap()
    .clone();
    expected_balance_account.approval_timeout_for_transfer = Duration::from_secs(6200);

    update_balance_account_policy(
        &mut context,
        BalanceAccountPolicyUpdate {
            approvals_required_for_transfer: 1,
            approval_timeout_for_transfer: Duration::from_secs(6200),
            transfer_approvers: vec![SlotId::new(1), SlotId::new(2)],
            signers_hash,
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        expected_balance_account,
        get_wallet(
            &mut context.test_context.pt_context.banks_client,
            &context.wallet_account.pubkey()
        )
        .await
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap()
    );

    expected_balance_account.approvals_required_for_transfer = 2;
    update_balance_account_policy(
        &mut context,
        BalanceAccountPolicyUpdate {
            approvals_required_for_transfer: 2,
            approval_timeout_for_transfer: Duration::from_secs(6200),
            transfer_approvers: vec![SlotId::new(1), SlotId::new(2)],
            signers_hash,
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        expected_balance_account,
        get_wallet(
            &mut context.test_context.pt_context.banks_client,
            &context.wallet_account.pubkey()
        )
        .await
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap()
    );
}

#[tokio::test]
async fn test_balance_account_policy_update_initiator_approval() {
    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(200000), true).await;
    let initiator_account = Keypair::from_base58_string(&context.approvers[2].to_base58_string());

    let signers_hash = hash_signers(&vec![
        context.approvers[1].pubkey_as_signer(),
        context.approvers[2].pubkey_as_signer(),
    ]);
    let multisig_op_account = init_balance_account_policy_update(
        &mut context,
        &initiator_account,
        BalanceAccountPolicyUpdate {
            approvals_required_for_transfer: 1,
            approval_timeout_for_transfer: Duration::from_secs(7200),
            transfer_approvers: vec![SlotId::new(1), SlotId::new(2)],
            signers_hash,
        },
    )
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

    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(200000), true).await;
    let initiator_account = Keypair::from_base58_string(&context.approvers[0].to_base58_string());

    let signers_hash_new = hash_signers(&vec![
        context.approvers[1].pubkey_as_signer(),
        context.approvers[2].pubkey_as_signer(),
    ]);

    let multisig_op_account = init_balance_account_policy_update(
        &mut context,
        &initiator_account,
        BalanceAccountPolicyUpdate {
            approvals_required_for_transfer: 1,
            approval_timeout_for_transfer: Duration::from_secs(7200),
            transfer_approvers: vec![SlotId::new(1), SlotId::new(2)],
            signers_hash: signers_hash_new,
        },
    )
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
async fn test_balance_account_policy_update_is_denied() {
    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(200000), true).await;

    let wallet = get_wallet(
        &mut context.test_context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;
    let balance_account = wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();

    let rent = context
        .test_context
        .pt_context
        .banks_client
        .get_rent()
        .await
        .unwrap();
    let multisig_op_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let signers_hash = hash_signers(&vec![
        context.approvers[1].pubkey_as_signer(),
        context.approvers[2].pubkey_as_signer(),
    ]);
    let update = BalanceAccountPolicyUpdate {
        approvals_required_for_transfer: 1,
        approval_timeout_for_transfer: Duration::from_secs(7200),
        transfer_approvers: vec![SlotId::new(1), SlotId::new(2)],
        signers_hash,
    };

    let balance_account_update_transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.test_context.pt_context.payer.pubkey(),
                &multisig_op_account.pubkey(),
                multisig_op_rent,
                MultisigOp::LEN as u64,
                &context.test_context.program_id,
            ),
            init_balance_account_policy_update_instruction(
                &context.test_context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &context.initiator_account.pubkey(),
                &context.test_context.pt_context.payer.pubkey(),
                context.balance_account_guid_hash,
                update.clone(),
            ),
        ],
        Some(&context.test_context.pt_context.payer.pubkey()),
        &[
            &context.test_context.pt_context.payer,
            &multisig_op_account,
            &context.initiator_account,
        ],
        context.test_context.pt_context.last_blockhash,
    );
    context
        .test_context
        .pt_context
        .banks_client
        .process_transaction(balance_account_update_transaction)
        .await
        .unwrap();

    approve_or_deny_n_of_n_multisig_op(
        context.test_context.pt_context.banks_client.borrow_mut(),
        &context.test_context.program_id,
        &multisig_op_account.pubkey(),
        vec![&context.approvers[0], &context.approvers[1]],
        &context.test_context.pt_context.payer,
        context.test_context.pt_context.last_blockhash,
        ApprovalDisposition::DENY,
        OperationDisposition::DENIED,
    )
    .await;

    // finalize the update
    let starting_rent_collector_balance = context
        .test_context
        .pt_context
        .banks_client
        .get_balance(context.test_context.pt_context.payer.pubkey())
        .await
        .unwrap();
    let op_account_balance = context
        .test_context
        .pt_context
        .banks_client
        .get_balance(multisig_op_account.pubkey())
        .await
        .unwrap();
    let finalize_update = Transaction::new_signed_with_payer(
        &[finalize_balance_account_policy_update_instruction(
            &context.test_context.program_id,
            &context.wallet_account.pubkey(),
            &multisig_op_account.pubkey(),
            &context.test_context.pt_context.payer.pubkey(),
            context.balance_account_guid_hash,
            update,
            None,
        )],
        Some(&context.test_context.pt_context.payer.pubkey()),
        &[&context.test_context.pt_context.payer],
        context.test_context.pt_context.last_blockhash,
    );
    context
        .test_context
        .pt_context
        .banks_client
        .process_transaction(finalize_update)
        .await
        .unwrap();

    // verify that balance account was not changed
    let wallet_after_update = get_wallet(
        &mut context.test_context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;
    let balance_account_after_update = wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();

    assert_eq!(
        balance_account_after_update.guid_hash,
        balance_account.guid_hash
    );
    assert_eq!(
        balance_account_after_update.approvals_required_for_transfer,
        balance_account.approvals_required_for_transfer
    );
    assert_eq!(
        balance_account_after_update.approval_timeout_for_transfer,
        balance_account.approval_timeout_for_transfer
    );
    assert_eq!(
        balance_account_after_update.name_hash,
        balance_account.name_hash
    );
    assert_eq!(
        wallet_after_update
            .get_transfer_approvers_keys(&balance_account_after_update)
            .to_set(),
        wallet
            .get_transfer_approvers_keys(&balance_account)
            .to_set()
    );
    assert_eq!(
        wallet_after_update
            .get_allowed_destinations(&balance_account_after_update)
            .to_set(),
        wallet.get_allowed_destinations(&balance_account).to_set()
    );

    // verify the multisig op account is closed
    assert!(context
        .test_context
        .pt_context
        .banks_client
        .get_account(multisig_op_account.pubkey())
        .await
        .unwrap()
        .is_none());

    // and that the remaining balance went to the rent collector (less the 5000 in signature fees for the finalize)
    let ending_rent_collector_balance = context
        .test_context
        .pt_context
        .banks_client
        .get_balance(context.test_context.pt_context.payer.pubkey())
        .await
        .unwrap();
    assert_eq!(
        starting_rent_collector_balance + op_account_balance - 5000,
        ending_rent_collector_balance
    );
}

#[tokio::test]
async fn invalid_balance_account_policy_updates() {
    let (mut context, _) = setup_balance_account_tests_and_finalize(None, true).await;
    let signers_hash = hash_signers(&vec![
        context.approvers[1].pubkey_as_signer(),
        context.approvers[2].pubkey_as_signer(),
    ]);
    // verify error when updating non existing balance account
    {
        let wrong_balance_account_guid_hash = BalanceAccountGuidHash::zero();
        let multisig_op_account = Keypair::new();
        verify_multisig_op_init_fails(
            &mut context.test_context.pt_context.banks_client,
            context.test_context.pt_context.last_blockhash,
            &context.test_context.pt_context.payer,
            &context.initiator_account,
            &multisig_op_account,
            init_balance_account_policy_update_instruction(
                &context.test_context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &context.initiator_account.pubkey(),
                &context.test_context.pt_context.payer.pubkey(),
                wrong_balance_account_guid_hash,
                BalanceAccountPolicyUpdate {
                    approvals_required_for_transfer: 1,
                    approval_timeout_for_transfer: Duration::from_secs(7200),
                    transfer_approvers: vec![SlotId::new(1), SlotId::new(2)],
                    signers_hash,
                },
            ),
            Custom(WalletError::BalanceAccountNotFound as u32),
        )
        .await;
    }
    // verify approvals required for transfer can't exceed configured approvers count
    {
        let multisig_op_account = Keypair::new();
        verify_multisig_op_init_fails(
            &mut context.test_context.pt_context.banks_client,
            context.test_context.pt_context.last_blockhash,
            &context.test_context.pt_context.payer,
            &context.initiator_account,
            &multisig_op_account,
            init_balance_account_policy_update_instruction(
                &context.test_context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &context.initiator_account.pubkey(),
                &context.test_context.pt_context.payer.pubkey(),
                context.balance_account_guid_hash,
                BalanceAccountPolicyUpdate {
                    approvals_required_for_transfer: 3,
                    approval_timeout_for_transfer: Duration::from_secs(7200),
                    transfer_approvers: vec![SlotId::new(1), SlotId::new(2)],
                    signers_hash,
                },
            ),
            Custom(WalletError::InvalidApproverCount as u32),
        )
        .await;
    }
    // verify not allowed to add transfer approver that is not configured as signer
    {
        let multisig_op_account = Keypair::new();
        verify_multisig_op_init_fails(
            &mut context.test_context.pt_context.banks_client,
            context.test_context.pt_context.last_blockhash,
            &context.test_context.pt_context.payer,
            &context.initiator_account,
            &multisig_op_account,
            init_balance_account_policy_update_instruction(
                &context.test_context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &context.initiator_account.pubkey(),
                &context.test_context.pt_context.payer.pubkey(),
                context.balance_account_guid_hash,
                BalanceAccountPolicyUpdate {
                    approvals_required_for_transfer: 1,
                    approval_timeout_for_transfer: Duration::from_secs(7200),
                    transfer_approvers: vec![SlotId::new(1), SlotId::new(3)],
                    signers_hash,
                },
            ),
            Custom(WalletError::UnknownSigner as u32),
        )
        .await;
    }
    // verify fails if signers hash does not match
    {
        let multisig_op_account = Keypair::new();
        verify_multisig_op_init_fails(
            &mut context.test_context.pt_context.banks_client,
            context.test_context.pt_context.last_blockhash,
            &context.test_context.pt_context.payer,
            &context.initiator_account,
            &multisig_op_account,
            init_balance_account_policy_update_instruction(
                &context.test_context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &context.initiator_account.pubkey(),
                &context.test_context.pt_context.payer.pubkey(),
                context.balance_account_guid_hash,
                BalanceAccountPolicyUpdate {
                    approvals_required_for_transfer: 1,
                    approval_timeout_for_transfer: Duration::from_secs(7200),
                    transfer_approvers: vec![SlotId::new(0), SlotId::new(1)],
                    signers_hash,
                },
            ),
            Custom(WalletError::InvalidSignersHash as u32),
        )
        .await;
    }
}

#[tokio::test]
async fn test_update_balance_account_name_happy_path() {
    let mut context = setup_balance_account_tests_and_finalize(None, true).await.0;
    let name_hash = BalanceAccountNameHash::new(&[1; 32]);

    update_balance_account_name_hash(&mut context, name_hash, None).await;
    verify_balance_account_name_hash(&mut context, &name_hash).await;
}

#[tokio::test]
async fn test_update_balance_account_name_fails_when_guid_invalid() {
    let mut context = setup_balance_account_tests_and_finalize(None, true).await.0;
    let name_hash = BalanceAccountNameHash::new(&[1; 32]);

    // set invalid GUID hash
    context.balance_account_guid_hash = BalanceAccountGuidHash::new(&[0; 32]);

    update_balance_account_name_hash(
        &mut context,
        name_hash,
        Some(Custom(WalletError::BalanceAccountNotFound as u32)),
    )
    .await;
}

#[tokio::test]
async fn test_update_balance_account_name_initiator_approval() {
    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(200000), true).await;
    let name_hash = BalanceAccountNameHash::new(&[1; 32]);
    let initiator_account = Keypair::from_base58_string(&context.approvers[2].to_base58_string());

    let multisig_op =
        init_balance_account_name_hash_update(&mut context, &initiator_account, name_hash)
            .await
            .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(
            &mut context.test_context.pt_context.banks_client,
            multisig_op,
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

    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(200000), true).await;
    let name_hash = BalanceAccountNameHash::new(&[1; 32]);
    let initiator_account = Keypair::from_base58_string(&context.approvers[0].to_base58_string());

    let multisig_op =
        init_balance_account_name_hash_update(&mut context, &initiator_account, name_hash)
            .await
            .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(
            &mut context.test_context.pt_context.banks_client,
            multisig_op,
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
