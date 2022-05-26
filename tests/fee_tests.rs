#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use solana_program::system_instruction;
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use std::borrow::BorrowMut;
use std::option::Option::None;
use std::time::Duration;
use strike_wallet::instruction::InitialWalletConfig;
use strike_wallet::model::balance_account::{BalanceAccount, BalanceAccountGuidHash};
use strike_wallet::model::multisig_op::{BooleanSetting, SlotUpdateType};
use strike_wallet::model::wallet::Signers;
use strike_wallet::utils::SlotId;
use {solana_program_test::tokio, solana_sdk::signature::Keypair};

#[tokio::test]
async fn test_fee_info_in_multisig_op() {
    // setup a wallet
    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];

    let initial_config = InitialWalletConfig {
        approvals_required_for_config: 2,
        approval_timeout_for_config: Duration::from_secs(3600),
        signers: vec![
            (SlotId::new(0), approvers[0].pubkey_as_signer()),
            (SlotId::new(1), approvers[1].pubkey_as_signer()),
        ],
        config_approvers: vec![SlotId::new(0), SlotId::new(1)],
    };

    let mut context = setup_wallet_test(40_000, initial_config).await;
    let expected_signers_after_add = Signers::from_vec(vec![
        (SlotId::new(0), approvers[0].pubkey_as_signer()),
        (SlotId::new(1), approvers[1].pubkey_as_signer()),
        (SlotId::new(2), approvers[2].pubkey_as_signer()),
    ]);

    update_signer(
        context.borrow_mut(),
        vec![&approvers[0], &approvers[1]],
        SlotUpdateType::SetIfEmpty,
        2,
        approvers[2].pubkey_as_signer(),
        Some(expected_signers_after_add),
        None,
        Some(12345),
        Some(BalanceAccountGuidHash::new(&hash_of(b"fee-account-guid"))),
    )
    .await;
}

#[tokio::test]
async fn test_fee_collection() {
    let mut context = setup_fee_tests().await;

    // transfer some SOL into the balance account to pay the fee
    let starting_balance: u64 = 10_000_000;
    let balance_account = &BalanceAccount::find_address(
        &context.wallet_guid_hash,
        &context.balance_account_guid_hash,
        &context.program_id,
    )
    .0;
    context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[system_instruction::transfer(
                &context.pt_context.payer.pubkey(),
                balance_account,
                starting_balance,
            )],
            Some(&context.pt_context.payer.pubkey()),
            &[&context.pt_context.payer],
            context.pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    // now run a multisig op with a fee
    let fee_account_guid_hash = Some(context.balance_account_guid_hash);
    account_settings_update(
        context.borrow_mut(),
        Some(BooleanSetting::On),
        None,
        None,
        Some(5_000_000),
        fee_account_guid_hash,
        None,
    )
    .await;

    // the balance account should be decremented by the fee amount
    let balance = context
        .pt_context
        .banks_client
        .get_balance(*balance_account)
        .await
        .unwrap();
    assert_eq!(balance, starting_balance - 5_000_000);

    // if we run another multisig op, not all of the fee will be spent as it will leave
    // the minimum amount in the account
    account_settings_update(
        context.borrow_mut(),
        Some(BooleanSetting::Off),
        None,
        None,
        Some(5_000_000),
        fee_account_guid_hash,
        Some(4109120),
    )
    .await;
    let balance = context
        .pt_context
        .banks_client
        .get_balance(*balance_account)
        .await
        .unwrap();
    assert_eq!(balance, 890880);

    // and if we run again, no fee should be collected
    account_settings_update(
        context.borrow_mut(),
        Some(BooleanSetting::On),
        None,
        None,
        Some(5_000_000),
        fee_account_guid_hash,
        Some(0),
    )
    .await;
    let balance = context
        .pt_context
        .banks_client
        .get_balance(*balance_account)
        .await
        .unwrap();
    assert_eq!(balance, 890880);
}
