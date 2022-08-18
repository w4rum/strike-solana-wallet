#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use std::time::Duration;

use solana_program::instruction::InstructionError::{Custom, MissingRequiredSignature};
use solana_sdk::transaction::TransactionError;

use crate::common::utils;
use itertools::Itertools;
use strike_wallet::error::WalletError;
use strike_wallet::instruction::InitialWalletConfig;
use strike_wallet::model::address_book::{AddressBook, DAppBook};
use strike_wallet::model::signer::Signer;
use strike_wallet::model::wallet::{Approvers, BalanceAccounts, Signers, Wallet, WalletGuidHash};
use strike_wallet::utils::SlotId;
use strike_wallet::version::VERSION;
use uuid::Uuid;
use {
    solana_program_test::tokio,
    solana_sdk::{
        pubkey::Pubkey,
        signature::{Keypair, Signer as SdkSigner},
    },
};

#[tokio::test]
async fn init_wallet() {
    let approvals_required_for_config = 2;
    let approval_timeout_for_config = Duration::from_secs(3600);
    let signers = vec![
        (SlotId::new(0), Signer::new(Pubkey::new_unique())),
        (SlotId::new(1), Signer::new(Pubkey::new_unique())),
        (SlotId::new(2), Signer::new(Pubkey::new_unique())),
    ];
    let config_approvers = signers.clone();

    let program_id = Keypair::new().pubkey();
    let program_upgrade_authority = Keypair::new();

    let (test_context, program_data_address) =
        start_program_test(program_id, 25_000, Some(program_upgrade_authority.pubkey())).await;
    let mut banks_client = test_context.banks_client;
    let payer = test_context.payer;
    let recent_blockhash = test_context.last_blockhash;

    let wallet_account = Keypair::new();

    let wallet_guid_hash = WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes()));

    utils::init_wallet(
        &mut banks_client,
        &payer,
        recent_blockhash,
        &program_id,
        &program_data_address,
        &program_upgrade_authority,
        &wallet_account,
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

    assert_eq!(
        get_wallet(&mut banks_client, &wallet_account.pubkey()).await,
        Wallet {
            is_initialized: true,
            version: VERSION,
            rent_return: payer.pubkey().clone(),
            wallet_guid_hash,
            signers: Signers::from_vec(signers),
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
}

#[tokio::test]
async fn init_wallet_has_to_be_signed_by_program_upgrade_authority() {
    let approvals_required_for_config = 2;
    let approval_timeout_for_config = Duration::from_secs(3600);
    let signers = vec![
        (SlotId::new(0), Signer::new(Pubkey::new_unique())),
        (SlotId::new(1), Signer::new(Pubkey::new_unique())),
        (SlotId::new(2), Signer::new(Pubkey::new_unique())),
    ];
    let config_approvers = signers.clone();

    let program_id = Keypair::new().pubkey();
    let program_upgrade_authority = Keypair::new().pubkey();

    let (test_context, program_data_address) =
        start_program_test(program_id, 25_000, Some(program_upgrade_authority)).await;
    let mut banks_client = test_context.banks_client;
    let payer = test_context.payer;
    let recent_blockhash = test_context.last_blockhash;

    let wallet_account = Keypair::new();

    let wallet_guid_hash = WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes()));

    assert_eq!(
        utils::init_wallet(
            &mut banks_client,
            &payer,
            recent_blockhash,
            &program_id,
            &program_data_address,
            &Keypair::new(),
            &wallet_account,
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
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(1, MissingRequiredSignature),
    );
}

#[tokio::test]
async fn invalid_wallet_initialization() {
    let mut test_context = setup_test(25_000).await;
    let wallet_account = Keypair::new();

    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let signers = vec![
        approvers[0].pubkey_as_signer(),
        approvers[1].pubkey_as_signer(),
        approvers[2].pubkey_as_signer(),
    ];

    // verify approvals required for config can't exceed configured approvers count
    assert_eq!(
        utils::init_wallet_from_context(
            &mut test_context,
            &wallet_account,
            WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
            InitialWalletConfig {
                approvals_required_for_config: 3,
                approval_timeout_for_config: Duration::from_secs(3600),
                signers: vec![(SlotId::new(0), signers[0]), (SlotId::new(1), signers[1]),],
                config_approvers: vec![SlotId::new(0), SlotId::new(1)],
            }
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(1, Custom(WalletError::InvalidApproverCount as u32)),
    );

    // verify it's not allowed to add a config approver that is not configured as signer
    assert_eq!(
        utils::init_wallet_from_context(
            &mut test_context,
            &wallet_account,
            WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
            InitialWalletConfig {
                approvals_required_for_config: 1,
                approval_timeout_for_config: Duration::from_secs(3600),
                signers: vec![(SlotId::new(0), signers[0]), (SlotId::new(1), signers[1]),],
                config_approvers: vec![SlotId::new(0), SlotId::new(2)],
            }
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(1, Custom(WalletError::UnknownSigner as u32)),
    );
}
