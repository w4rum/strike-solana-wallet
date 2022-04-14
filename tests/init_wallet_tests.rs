#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils::*;

use std::time::Duration;

use solana_program::instruction::InstructionError::Custom;
use solana_sdk::transaction::TransactionError;

use crate::common::utils;
use itertools::Itertools;
use strike_wallet::error::WalletError;
use strike_wallet::instruction::InitialWalletConfig;
use strike_wallet::model::address_book::{AddressBook, DAppBook};
use strike_wallet::model::signer::Signer;
use strike_wallet::model::wallet::{Approvers, BalanceAccounts, Signers, Wallet};
use strike_wallet::utils::SlotId;
use strike_wallet::version::VERSION;
use {
    solana_program_test::{processor, tokio, ProgramTest},
    solana_sdk::{
        pubkey::Pubkey,
        signature::{Keypair, Signer as SdkSigner},
    },
    strike_wallet::processor::Processor,
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
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(25_000);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;
    let wallet_account = Keypair::new();
    let assistant_account = Keypair::new();

    utils::init_wallet(
        &mut banks_client,
        &payer,
        recent_blockhash,
        &program_id,
        &wallet_account,
        &assistant_account,
        InitialWalletConfig {
            approvals_required_for_config: approvals_required_for_config.clone(),
            approval_timeout_for_config,
            signers: signers.clone(),
            config_approvers: config_approvers.clone(),
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
            config_policy_update_locked: false,
            dapp_book: DAppBook::from_vec(vec![]),
        }
    );
}

#[tokio::test]
async fn invalid_wallet_initialization() {
    let program_id = Keypair::new().pubkey();
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(40_000);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;
    let wallet_account = Keypair::new();
    let assistant_account = Keypair::new();

    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];
    let signers = vec![
        approvers[0].pubkey_as_signer(),
        approvers[1].pubkey_as_signer(),
        approvers[2].pubkey_as_signer(),
    ];

    // verify approvals required for config can't exceed configured approvers count
    assert_eq!(
        utils::init_wallet(
            &mut banks_client,
            &payer,
            recent_blockhash,
            &program_id,
            &wallet_account,
            &assistant_account,
            InitialWalletConfig {
                approvals_required_for_config: 3,
                approval_timeout_for_config: Duration::from_secs(3600),
                signers: vec![(SlotId::new(0), signers[0]), (SlotId::new(1), signers[1]),],
                config_approvers: vec![(SlotId::new(0), signers[0]), (SlotId::new(1), signers[1]),],
            }
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(1, Custom(WalletError::InvalidApproverCount as u32)),
    );

    // verify it's not allowed to add a config approver that is not configured as signer
    assert_eq!(
        utils::init_wallet(
            &mut banks_client,
            &payer,
            recent_blockhash,
            &program_id,
            &wallet_account,
            &assistant_account,
            InitialWalletConfig {
                approvals_required_for_config: 1,
                approval_timeout_for_config: Duration::from_secs(3600),
                signers: vec![(SlotId::new(0), signers[0]), (SlotId::new(1), signers[1]),],
                config_approvers: vec![(SlotId::new(0), signers[0]), (SlotId::new(1), signers[2]),],
            }
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(1, Custom(WalletError::UnknownSigner as u32)),
    );
}
