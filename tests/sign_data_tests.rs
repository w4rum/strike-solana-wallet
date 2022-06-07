#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use std::borrow::BorrowMut;
use std::time::Duration;

use crate::common::utils;
use solana_program::program_pack::Pack;
use solana_program::system_instruction;
use solana_sdk::account::ReadableAccount;
use solana_sdk::signature::Signer;
use std::collections::HashSet;
use strike_wallet::instruction::InitialWalletConfig;
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, MultisigOp, OperationDisposition,
};
use strike_wallet::model::wallet::WalletGuidHash;
use strike_wallet::utils::SlotId;
use strike_wallet::version::VERSION;
use uuid::Uuid;
use {
    solana_program_test::tokio,
    solana_sdk::{signature::Keypair, transaction::Transaction},
};

#[tokio::test]
async fn test_sign_data() {
    let mut context = setup_test(20_000).await;

    let wallet_account = Keypair::new();
    let assistant_account = Keypair::new();

    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let signers = vec![
        approvers[0].pubkey_as_signer(),
        approvers[1].pubkey_as_signer(),
        approvers[2].pubkey_as_signer(),
    ];

    utils::init_wallet(
        &mut context.banks_client,
        &context.payer,
        context.recent_blockhash,
        &context.program_id,
        &wallet_account,
        &assistant_account,
        WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
        InitialWalletConfig {
            approvals_required_for_config: 2,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers: vec![
                (SlotId::new(0), signers[0]),
                (SlotId::new(1), signers[1]),
                (SlotId::new(2), signers[2]),
            ],
            config_approvers: vec![SlotId::new(0), SlotId::new(1)],
        },
    )
    .await
    .unwrap();

    let rent = context.banks_client.get_rent().await.unwrap();
    let multisig_account_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();

    let data: Vec<u8> = vec![1, 2, 3, 4];

    let init_transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.payer.pubkey(),
                &multisig_op_account.pubkey(),
                multisig_account_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            init_sign_data_instruction(
                &context.program_id,
                &wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &approvers[2].pubkey(),
                &context.payer.pubkey(),
                &data,
            ),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer, &multisig_op_account, &approvers[2]],
        context.recent_blockhash,
    );
    context
        .banks_client
        .process_transaction(init_transaction)
        .await
        .unwrap();

    // verify the multisig op account data
    let multisig_op = MultisigOp::unpack_from_slice(
        context
            .banks_client
            .get_account(multisig_op_account.pubkey())
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();
    assert!(multisig_op.is_initialized);
    assert_eq!(
        multisig_op.disposition_records.to_set(),
        HashSet::from([
            ApprovalDispositionRecord {
                approver: approvers[0].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
            ApprovalDispositionRecord {
                approver: approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ])
    );
    assert_eq!(multisig_op.dispositions_required, 2);
    assert_eq!(multisig_op.version, VERSION);
    assert_eq!(multisig_op.initiator, approvers[2].pubkey());
    assert_eq!(multisig_op.rent_return, context.payer.pubkey());
    assert!(multisig_op.fee_account_guid_hash.is_none());
    assert_eq!(multisig_op.fee_amount, 0);

    approve_or_deny_n_of_n_multisig_op(
        context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account.pubkey(),
        vec![&approvers[0], &approvers[1]],
        &context.payer,
        context.recent_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // finalize
    let starting_rent_collector_balance = context
        .banks_client
        .get_balance(context.payer.pubkey())
        .await
        .unwrap();
    let op_account_balance = context
        .banks_client
        .get_balance(multisig_op_account.pubkey())
        .await
        .unwrap();
    let finalize_transaction = Transaction::new_signed_with_payer(
        &[finalize_sign_data_instruction(
            &context.program_id,
            &wallet_account.pubkey(),
            &multisig_op_account.pubkey(),
            &context.payer.pubkey(),
            &data,
            None,
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.recent_blockhash,
    );
    context
        .banks_client
        .process_transaction(finalize_transaction)
        .await
        .unwrap();

    // verify the multisig op account is closed
    assert!(context
        .banks_client
        .get_account(multisig_op_account.pubkey())
        .await
        .unwrap()
        .is_none());
    // and that the remaining balance went to the rent collector (less the 5000 in signature fees for the finalize)
    let ending_rent_collector_balance = context
        .banks_client
        .get_balance(context.payer.pubkey())
        .await
        .unwrap();
    assert_eq!(
        starting_rent_collector_balance + op_account_balance - 5000,
        ending_rent_collector_balance
    );
}
