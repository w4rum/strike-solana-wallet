#![cfg(feature = "test-bpf")]

use std::time::Duration;

use itertools::Itertools;
use solana_program::bpf_loader_upgradeable::{deploy_with_max_program_len, upgrade};
use solana_program::hash::Hash;
use solana_program::instruction::InstructionError;
use solana_program::instruction::InstructionError::{Custom, UninitializedAccount};
use solana_program::program_pack::Pack;
use solana_program::pubkey::PUBKEY_BYTES;
use solana_program::system_instruction;
use solana_program_test::{find_file, processor, read_file, BanksClientError, ProgramTestContext};
use solana_sdk::account::{AccountSharedData, ReadableAccount, WritableAccount};
use solana_sdk::transaction::{Transaction, TransactionError};
use uuid::Uuid;

pub use common::instructions::*;
pub use common::utils::*;
use strike_wallet::error::WalletError;
use strike_wallet::instruction::InitialWalletConfig;
use strike_wallet::model::address_book::{AddressBook, DAppBook};
use strike_wallet::model::signer::Signer;
use strike_wallet::model::wallet::{Approvers, BalanceAccounts, Signers, Wallet, WalletGuidHash};
use strike_wallet::utils::SlotId;
use {
    solana_program_test::{tokio, ProgramTest},
    solana_sdk::{
        pubkey::Pubkey,
        signature::{Keypair, Signer as SdkSigner},
    },
    strike_wallet::processor::Processor,
};

use crate::common::{instructions, utils};
use crate::tokio::time::sleep;

mod common;

#[tokio::test]
async fn migrate_account() {
    // first call init_wallet
    let approvals_required_for_config = 2;
    let approval_timeout_for_config = Duration::from_secs(3600);
    let signers = vec![
        (SlotId::new(0), Signer::new(Pubkey::new_unique())),
        (SlotId::new(1), Signer::new(Pubkey::new_unique())),
        (SlotId::new(2), Signer::new(Pubkey::new_unique())),
    ];
    let config_approvers = signers.clone();

    let program_account = Keypair::new();
    let program_id = program_account.pubkey();
    let mut pt = ProgramTest::default();
    pt.set_compute_max_units(25_000);
    let mut pt_context = pt.start_with_context().await;

    // deploy program as upgradeable
    let wallet_account = Keypair::new();
    let assistant_account = Keypair::new();

    let program_file = find_file(&"strike_wallet.so").unwrap();
    let data = read_file(&program_file);
    let data_len = data.len();

    let buffer_account = Keypair::new();
    create_program_buffer(&mut pt_context, &buffer_account, data).await;

    let rent = pt_context.banks_client.get_rent().await.unwrap();
    let program_rent = rent.minimum_balance(data_len * 2);
    pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            deploy_with_max_program_len(
                &pt_context.payer.pubkey(),
                &program_id,
                &buffer_account.pubkey(),
                &pt_context.payer.pubkey(),
                program_rent,
                data_len * 2,
            )
            .unwrap()
            .as_slice(),
            Some(&pt_context.payer.pubkey()),
            &[&pt_context.payer, &program_account],
            pt_context.last_blockhash,
        ))
        .await
        .unwrap();
    let wallet_guid_hash = WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes()));
    utils::init_wallet(
        &mut pt_context.banks_client,
        &pt_context.payer,
        pt_context.last_blockhash,
        &program_id,
        &wallet_account,
        &assistant_account,
        wallet_guid_hash,
        InitialWalletConfig {
            approvals_required_for_config: approvals_required_for_config.clone(),
            approval_timeout_for_config,
            signers: signers.clone(),
            config_approvers: config_approvers
                .clone()
                .iter()
                .map(|signer| signer.0)
                .collect_vec(),
        },
    )
    .await
    .unwrap();

    // "upgrade" the program to the contents of the "version_0" .so, which is
    // simply the current build with the version hacked to be 0
    let program_file = find_file(&"strike_wallet_version_0.so").unwrap();
    let update_data = read_file(&program_file);
    let upgrade_buffer_account = Keypair::new();
    create_program_buffer(&mut pt_context, &upgrade_buffer_account, update_data).await;

    pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[upgrade(
                &program_id,
                &upgrade_buffer_account.pubkey(),
                &pt_context.payer.pubkey(),
                &pt_context.payer.pubkey(),
            )],
            Some(&pt_context.payer.pubkey()),
            &[&pt_context.payer],
            pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    // run the migration
    // need a target account
    let upgraded_wallet_account = Keypair::new();
    let rent = pt_context.banks_client.get_rent().await.unwrap();
    let program_rent = rent.minimum_balance(Wallet::LEN);

    let transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &pt_context.payer.pubkey(),
                &upgraded_wallet_account.pubkey(),
                program_rent,
                Wallet::LEN as u64,
                &program_id,
            ),
            instructions::migrate_account(
                &program_id,
                &wallet_account.pubkey(),
                &upgraded_wallet_account.pubkey(),
                &pt_context.payer.pubkey(),
            ),
        ],
        Some(&pt_context.payer.pubkey()),
        &[&pt_context.payer, &upgraded_wallet_account],
        pt_context.last_blockhash,
    );
    pt_context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();

    assert_eq!(
        get_wallet(
            &mut pt_context.banks_client,
            &upgraded_wallet_account.pubkey()
        )
        .await,
        Wallet {
            is_initialized: true,
            version: 0,
            rent_return: pt_context.payer.pubkey().clone(),
            wallet_guid_hash,
            signers: Signers::from_vec(signers),
            assistant: assistant_account.pubkey_as_signer(),
            address_book: AddressBook::new(),
            approvals_required_for_config,
            approval_timeout_for_config,
            config_approvers: Approvers::from_enabled_vec(
                config_approvers
                    .into_iter()
                    .map(|(slot_id, _)| slot_id)
                    .collect_vec()
            ),
            balance_accounts: BalanceAccounts::new(),
            dapp_book: DAppBook::from_vec(vec![]),
        }
    );

    let fee_payer_starting_balance = pt_context
        .banks_client
        .get_balance(pt_context.payer.pubkey())
        .await
        .unwrap();
    let wallet_account_balance = pt_context
        .banks_client
        .get_balance(wallet_account.pubkey())
        .await
        .unwrap();

    // cleanup the source wallet account
    pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[cleanup_account(
                &program_id,
                &upgraded_wallet_account.pubkey(),
                &wallet_account.pubkey(),
                &pt_context.payer.pubkey(),
            )],
            Some(&pt_context.payer.pubkey()),
            &[&pt_context.payer],
            pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    assert!(pt_context
        .banks_client
        .get_account(wallet_account.pubkey())
        .await
        .unwrap()
        .is_none());

    let fee_payer_ending_balance = pt_context
        .banks_client
        .get_balance(pt_context.payer.pubkey())
        .await
        .unwrap();
    assert_eq!(
        fee_payer_ending_balance,
        fee_payer_starting_balance + wallet_account_balance - 5000
    )
}

#[tokio::test]
async fn test_migrate_errors() {
    let approvals_required_for_config = 2;
    let approval_timeout_for_config = Duration::from_secs(3600);
    let signers = vec![
        (SlotId::new(0), Signer::new(Pubkey::new_unique())),
        (SlotId::new(1), Signer::new(Pubkey::new_unique())),
        (SlotId::new(2), Signer::new(Pubkey::new_unique())),
    ];
    let config_approvers = signers.clone();

    let program_id = Keypair::new().pubkey();
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(25_000);
    let mut pt_context = pt.start_with_context().await;
    let wallet_account = Keypair::new();
    let assistant_account = Keypair::new();

    utils::init_wallet(
        &mut pt_context.banks_client,
        &pt_context.payer,
        pt_context.last_blockhash,
        &program_id,
        &wallet_account,
        &assistant_account,
        WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
        InitialWalletConfig {
            approvals_required_for_config: approvals_required_for_config.clone(),
            approval_timeout_for_config,
            signers: signers.clone(),
            config_approvers: config_approvers
                .clone()
                .iter()
                .map(|signer| signer.0)
                .collect_vec(),
        },
    )
    .await
    .unwrap();

    let destination_wallet_account = Keypair::new();
    let rent = pt_context.banks_client.get_rent().await.unwrap();
    let program_rent = rent.minimum_balance(Wallet::LEN);

    // create the destination account first in its own transaction
    pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[system_instruction::create_account(
                &pt_context.payer.pubkey(),
                &destination_wallet_account.pubkey(),
                program_rent,
                Wallet::LEN as u64,
                &program_id,
            )],
            Some(&pt_context.payer.pubkey()),
            &[&pt_context.payer, &destination_wallet_account],
            pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    let blockhash = pt_context.last_blockhash;
    // cannot call migrate from the current version
    assert_eq!(
        process_migrate_account_transaction(
            &mut pt_context,
            &program_id,
            &wallet_account,
            &destination_wallet_account,
            blockhash
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::AccountVersionMismatch as u32)),
    );

    // alter the version of the source account so it is not the current version, but an unknown version
    let mut wallet_account_shared_data = AccountSharedData::from(
        pt_context
            .banks_client
            .get_account(wallet_account.pubkey())
            .await
            .unwrap()
            .unwrap(),
    );
    let mut wallet = Wallet::unpack_from_slice(wallet_account_shared_data.data()).unwrap();
    wallet.version = 0;
    wallet.pack_into_slice(wallet_account_shared_data.data_as_mut_slice());
    pt_context.set_account(&wallet_account.pubkey(), &wallet_account_shared_data);

    // we need a fresh blockhash so the transaction executes again
    let blockhash = wait_for_new_blockhash(&mut pt_context).await;
    assert_eq!(
        process_migrate_account_transaction(
            &mut pt_context,
            &program_id,
            &wallet_account,
            &destination_wallet_account,
            blockhash
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::UnknownVersion as u32)),
    );

    // set the initialized bit on the destination account
    let mut destination_wallet_account_shared_data = AccountSharedData::from(
        pt_context
            .banks_client
            .get_account(destination_wallet_account.pubkey())
            .await
            .unwrap()
            .unwrap(),
    );
    destination_wallet_account_shared_data.data_mut()[0] = 1;
    pt_context.set_account(
        &destination_wallet_account.pubkey(),
        &destination_wallet_account_shared_data,
    );

    // we need a fresh blockhash so the transaction executes again
    let blockhash = wait_for_new_blockhash(&mut pt_context).await;
    assert_eq!(
        process_migrate_account_transaction(
            &mut pt_context,
            &program_id,
            &wallet_account,
            &destination_wallet_account,
            blockhash
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(0, InstructionError::AccountAlreadyInitialized)
    );
}

#[tokio::test]
async fn test_cleanup_errors() {
    let approvals_required_for_config = 1;
    let approval_timeout_for_config = Duration::from_secs(3600);
    let signers = vec![(SlotId::new(0), Signer::new(Pubkey::new_unique()))];
    let config_approvers = signers.clone();

    let program_id = Keypair::new().pubkey();
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(25_000);
    let mut pt_context = pt.start_with_context().await;
    let wallet_account = Keypair::new();
    let assistant_account = Keypair::new();

    utils::init_wallet(
        &mut pt_context.banks_client,
        &pt_context.payer,
        pt_context.last_blockhash,
        &program_id,
        &wallet_account,
        &assistant_account,
        WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
        InitialWalletConfig {
            approvals_required_for_config: approvals_required_for_config.clone(),
            approval_timeout_for_config,
            signers: signers.clone(),
            config_approvers: config_approvers
                .clone()
                .iter()
                .map(|signer| signer.0)
                .collect_vec(),
        },
    )
    .await
    .unwrap();

    // cannot clean up a wallet account for the current program version
    assert_eq!(
        pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[cleanup_account(
                    &program_id,
                    &wallet_account.pubkey(),
                    &wallet_account.pubkey(),
                    &pt_context.payer.pubkey(),
                )],
                Some(&pt_context.payer.pubkey()),
                &[&pt_context.payer],
                pt_context.last_blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::AccountVersionMismatch as u32))
    );

    // cannot cleanup an uninitialized account
    let uninitialized_account = Keypair::new();
    let rent = pt_context.banks_client.get_rent().await.unwrap();
    let wallet_account_rent = rent.minimum_balance(Wallet::LEN);

    pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[system_instruction::create_account(
                &pt_context.payer.pubkey(),
                &uninitialized_account.pubkey(),
                wallet_account_rent,
                Wallet::LEN as u64,
                &program_id,
            )],
            Some(&pt_context.payer.pubkey()),
            &[&pt_context.payer, &uninitialized_account],
            pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    assert_eq!(
        pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[cleanup_account(
                    &program_id,
                    &wallet_account.pubkey(),
                    &uninitialized_account.pubkey(),
                    &pt_context.payer.pubkey(),
                )],
                Some(&pt_context.payer.pubkey()),
                &[&pt_context.payer],
                pt_context.last_blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, UninitializedAccount)
    );

    // must pass correct rent return account
    // (need to modify uninitialized account to be initialized so we can get past previous error)
    let mut uninitialized_wallet_account_shared_data = AccountSharedData::from(
        pt_context
            .banks_client
            .get_account(uninitialized_account.pubkey())
            .await
            .unwrap()
            .unwrap(),
    );
    uninitialized_wallet_account_shared_data.data_as_mut_slice()[0] = 1;
    pt_context.set_account(
        &uninitialized_account.pubkey(),
        &uninitialized_wallet_account_shared_data,
    );

    let blockhash = wait_for_new_blockhash(&mut pt_context).await;

    assert_eq!(
        pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[cleanup_account(
                    &program_id,
                    &wallet_account.pubkey(),
                    &uninitialized_account.pubkey(),
                    &pt_context.payer.pubkey(),
                )],
                Some(&pt_context.payer.pubkey()),
                &[&pt_context.payer],
                blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::AccountNotRecognized as u32))
    );

    // cleanup account must have same wallet guid hash as the wallet account
    // first we modify it so it has the correct rent_return address
    uninitialized_wallet_account_shared_data.data_as_mut_slice()[5..5 + PUBKEY_BYTES]
        .copy_from_slice(pt_context.payer.pubkey().as_ref());

    pt_context.set_account(
        &uninitialized_account.pubkey(),
        &uninitialized_wallet_account_shared_data,
    );

    let blockhash = wait_for_new_blockhash(&mut pt_context).await;

    assert_eq!(
        pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[cleanup_account(
                    &program_id,
                    &wallet_account.pubkey(),
                    &uninitialized_account.pubkey(),
                    &pt_context.payer.pubkey(),
                )],
                Some(&pt_context.payer.pubkey()),
                &[&pt_context.payer],
                blockhash,
            ))
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(0, Custom(WalletError::WalletGuidHashMismatch as u32))
    );
}

async fn wait_for_new_blockhash(pt_context: &mut ProgramTestContext) -> Hash {
    let last_blockhash = pt_context
        .banks_client
        .get_latest_blockhash()
        .await
        .unwrap();
    while last_blockhash
        == pt_context
            .banks_client
            .get_latest_blockhash()
            .await
            .unwrap()
    {
        sleep(Duration::from_millis(10)).await;
    }
    pt_context
        .banks_client
        .get_latest_blockhash()
        .await
        .unwrap()
}

async fn process_migrate_account_transaction(
    pt_context: &mut ProgramTestContext,
    program_id: &Pubkey,
    wallet_account: &Keypair,
    destination_wallet_account: &Keypair,
    blockhash: Hash,
) -> Result<(), BanksClientError> {
    pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[instructions::migrate_account(
                program_id,
                &wallet_account.pubkey(),
                &destination_wallet_account.pubkey(),
                &pt_context.payer.pubkey(),
            )],
            Some(&pt_context.payer.pubkey()),
            &[&pt_context.payer],
            blockhash,
        ))
        .await
}
