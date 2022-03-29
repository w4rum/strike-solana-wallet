#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use solana_program::instruction::InstructionError::Custom;
use solana_program_test::tokio;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use strike_wallet::error::WalletError;
use strike_wallet::instruction::AddressBookUpdate;
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, BooleanSetting, OperationDisposition,
};

#[tokio::test]
async fn test_address_book_update() {
    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(64000)).await;

    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;

    let initial_entries = wallet.address_book.filled_slots().clone();
    verify_address_book(&mut context, initial_entries.clone(), vec![]).await;

    // remove all the entries
    modify_address_book_and_whitelist(
        &mut context,
        vec![],
        wallet.address_book.filled_slots(),
        vec![],
        vec![],
        None,
    )
    .await;
    verify_address_book(&mut context, vec![], vec![]).await;

    // turn white list on
    account_settings_update(&mut context, Some(BooleanSetting::On), None, None).await;

    // add 2 entries back and also whitelist
    modify_address_book_and_whitelist(
        &mut context,
        initial_entries.clone(),
        vec![],
        initial_entries.clone(),
        vec![],
        None,
    )
    .await;

    verify_address_book(
        &mut context,
        initial_entries.clone(),
        vec![
            initial_entries[0].1,
            initial_entries[1].1,
            initial_entries[2].1,
        ],
    )
    .await;

    // remove from whitelist and address book together
    modify_address_book_and_whitelist(
        &mut context,
        vec![],
        initial_entries.clone(),
        vec![],
        initial_entries.clone(),
        None,
    )
    .await;

    verify_address_book(&mut context, vec![], vec![]).await;

    // add 1 entry back and also whitelist
    modify_address_book_and_whitelist(
        &mut context,
        vec![initial_entries[0]],
        vec![],
        vec![initial_entries[0]],
        vec![],
        None,
    )
    .await;
    verify_address_book(
        &mut context,
        vec![initial_entries[0]],
        vec![initial_entries[0].1],
    )
    .await;

    // add and remove in same request
    modify_address_book_and_whitelist(
        &mut context,
        vec![initial_entries[1]],
        vec![initial_entries[0]],
        vec![initial_entries[1]],
        vec![initial_entries[0]],
        None,
    )
    .await;
    verify_address_book(
        &mut context,
        vec![initial_entries[1]],
        vec![initial_entries[1].1],
    )
    .await;
}

#[tokio::test]
async fn test_address_book_failures() {
    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(40000)).await;

    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;

    // whitelist both entries, but whitelisting not on
    modify_address_book_and_whitelist(
        &mut context,
        vec![],
        vec![],
        wallet.address_book.filled_slots(),
        vec![],
        Some(Custom(WalletError::WhitelistDisabled as u32)),
    )
    .await;

    // turn on whitelisting and add the 2 entries
    account_settings_update(&mut context, Some(BooleanSetting::On), None, None).await;
    modify_address_book_and_whitelist(
        &mut context,
        vec![],
        vec![],
        wallet.address_book.filled_slots(),
        vec![],
        None,
    )
    .await;

    // try to remove a address book entry - will fail since its whitelisted
    modify_address_book_and_whitelist(
        &mut context,
        vec![],
        wallet.address_book.filled_slots(),
        vec![],
        vec![],
        Some(Custom(WalletError::DestinationInUse as u32)),
    )
    .await;

    // try to put a key into a filled slot with a different entry
    modify_address_book_and_whitelist(
        &mut context,
        vec![(
            wallet.address_book.filled_slots()[0].0,
            wallet.address_book.filled_slots()[1].1,
        )],
        vec![],
        vec![],
        vec![],
        Some(Custom(WalletError::SlotCannotBeInserted as u32)),
    )
    .await;

    // unwhitelist and remove first entry
    modify_address_book_and_whitelist(
        &mut context,
        vec![],
        vec![wallet.address_book.filled_slots()[0]],
        vec![],
        vec![wallet.address_book.filled_slots()[0]],
        None,
    )
    .await;

    // now try to whitelist - but its not in address book
    modify_address_book_and_whitelist(
        &mut context,
        vec![],
        vec![],
        vec![wallet.address_book.filled_slots()[0]],
        vec![],
        Some(Custom(WalletError::InvalidSlot as u32)),
    )
    .await;
}

#[tokio::test]
async fn test_address_book_update_initiator_approval() {
    let (mut context, _) = setup_balance_account_tests_and_finalize(Some(64000)).await;
    let initiator_account = Keypair::from_base58_string(&context.approvers[2].to_base58_string());

    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;

    let multisig_op_account = init_address_book_update(
        &mut context,
        &initiator_account,
        AddressBookUpdate {
            add_address_book_entries: vec![],
            remove_address_book_entries: wallet.address_book.filled_slots(),
            balance_account_whitelist_updates: vec![],
        },
    )
    .await
    .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(&mut context.pt_context.banks_client, multisig_op_account).await,
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

    let initiator_account = Keypair::from_base58_string(&context.approvers[0].to_base58_string());
    let multisig_op_account = init_address_book_update(
        &mut context,
        &initiator_account,
        AddressBookUpdate {
            add_address_book_entries: vec![],
            remove_address_book_entries: wallet.address_book.filled_slots(),
            balance_account_whitelist_updates: vec![],
        },
    )
    .await
    .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(&mut context.pt_context.banks_client, multisig_op_account).await,
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
