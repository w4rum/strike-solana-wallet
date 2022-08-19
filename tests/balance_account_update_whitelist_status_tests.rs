#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use solana_program::instruction::InstructionError::Custom;
use solana_program_test::tokio;
use solana_sdk::signature::Keypair;
use solana_sdk::transaction::TransactionError;
use std::borrow::BorrowMut;
use std::option::Option::None;
use strike_wallet::error::WalletError;
use strike_wallet::model::{balance_account::BalanceAccountGuidHash, multisig_op::BooleanSetting};
use strike_wallet::utils::SlotId;

#[tokio::test]
async fn test_whitelist_status() {
    let (mut context, balance_account) = setup_balance_account_tests_and_finalize(None, true).await;

    // status is off by default
    verify_whitelist_status(&mut context, BooleanSetting::Off, 0).await;

    // transfer should go through
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());
    let (_, result) =
        setup_transfer_test(context.borrow_mut(), initiator, &balance_account, None, 123).await;
    result.unwrap();

    // add a whitelisted destination, should fail since whitelisting on
    let destination_to_add = context.allowed_destination;
    modify_balance_account_address_whitelist(
        &mut context,
        vec![(SlotId::new(0), destination_to_add)],
        Some(Custom(WalletError::WhitelistDisabled as u32)),
    )
    .await;

    // turn whitelisting on should be able to add destination now
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
    verify_whitelist_status(&mut context, BooleanSetting::On, 0).await;
    modify_balance_account_address_whitelist(
        &mut context,
        vec![(SlotId::new(0), destination_to_add)],
        None,
    )
    .await;

    // try to turn it off - should fail since there are whitelisted destinations
    account_settings_update(
        &mut context,
        Some(BooleanSetting::Off),
        None,
        Some(Custom(WalletError::WhitelistedAddressInUse as u32)),
        None,
        None,
        None,
    )
    .await;

    // remove a whitelisted destination, status should still be On even though whitelist is empty
    modify_balance_account_address_whitelist(&mut context, vec![], None).await;

    verify_whitelist_status(&mut context, BooleanSetting::On, 0).await;

    // make sure transfer fails
    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());
    let (_, result) =
        setup_transfer_test(context.borrow_mut(), initiator, &balance_account, None, 123).await;
    assert_eq!(
        result.unwrap_err().unwrap(),
        TransactionError::InstructionError(1, Custom(WalletError::DestinationNotAllowed as u32)),
    );

    // explicitly turn it off and verify transfer succeeds
    account_settings_update(
        &mut context,
        Some(BooleanSetting::Off),
        None,
        None,
        None,
        None,
        None,
    )
    .await;
    verify_whitelist_status(&mut context, BooleanSetting::Off, 0).await;

    let initiator = &Keypair::from_base58_string(&context.approvers[2].to_base58_string());
    let (_, result) =
        setup_transfer_test(context.borrow_mut(), initiator, &balance_account, None, 123).await;
    result.unwrap();

    // explicitly turn it on
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
    verify_whitelist_status(&mut context, BooleanSetting::On, 0).await;
}

#[tokio::test]
async fn test_modify_whitelist_when_account_guid_invalid() {
    let mut context = setup_balance_account_tests_and_finalize(None, true).await.0;

    // status is off by default
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
    verify_whitelist_status(&mut context, BooleanSetting::On, 0).await;

    // set invalid GUID hash
    context.balance_account_guid_hash = BalanceAccountGuidHash::new(&[0; 32]);

    // add a whitelisted destination, should fail due to invalid account guid.
    let destination_to_add = context.allowed_destination;
    modify_balance_account_address_whitelist(
        &mut context,
        vec![(SlotId::new(0), destination_to_add)],
        Some(Custom(WalletError::BalanceAccountNotFound as u32)),
    )
    .await;
}
