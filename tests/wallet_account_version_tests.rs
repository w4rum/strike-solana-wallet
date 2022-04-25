#![cfg(feature = "test-bpf")]

use std::time::Duration;

use solana_program::instruction::InstructionError::Custom;
use solana_program::program_pack::Pack;
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::account::{AccountSharedData, ReadableAccount, WritableAccount};
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::TransactionError;
use uuid::Uuid;

pub use common::instructions::*;
pub use common::utils;
pub use common::utils::*;
use strike_wallet::error::WalletError;
use strike_wallet::instruction::{InitialWalletConfig, WalletConfigPolicyUpdate};
use strike_wallet::model::wallet::{Wallet, WalletGuidHash};
use strike_wallet::processor::Processor;
use strike_wallet::utils::SlotId;

mod common;

#[tokio::test]
async fn test_wallet_account_version_mismatch() {
    let program_id = Keypair::new().pubkey();
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(25_000);

    let mut pt_context = pt.start_with_context().await;

    let wallet_account = Keypair::new();
    let assistant_account = Keypair::new();

    let approvers = vec![Keypair::new()];
    let signers = vec![approvers[0].pubkey_as_signer()];

    utils::init_wallet(
        &mut pt_context.banks_client,
        &pt_context.payer,
        pt_context.last_blockhash,
        &program_id,
        &wallet_account,
        &assistant_account,
        WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
        InitialWalletConfig {
            approvals_required_for_config: 1,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers: vec![(SlotId::new(0), signers[0])],
            config_approvers: vec![SlotId::new(0)],
        },
    )
    .await
    .unwrap();

    // modify the version in the wallet account
    let mut wallet_account_shared_data = AccountSharedData::from(
        pt_context
            .banks_client
            .get_account(wallet_account.pubkey())
            .await
            .unwrap()
            .unwrap(),
    );
    let mut wallet = Wallet::unpack_from_slice(wallet_account_shared_data.data()).unwrap();
    let correct_version = wallet.version;
    let bad_version = correct_version + 1;
    wallet.version = bad_version;
    wallet.pack_into_slice(wallet_account_shared_data.data_as_mut_slice());
    pt_context.set_account(&wallet_account.pubkey(), &wallet_account_shared_data);

    let update = WalletConfigPolicyUpdate {
        approvals_required_for_config: 1,
        approval_timeout_for_config: Duration::from_secs(7200),
        config_approvers: vec![SlotId::new(1)],
        signers_hash: hash_signers(&vec![signers[0]]),
    };

    let rent = pt_context.banks_client.get_rent().await.unwrap();
    let banks_client = pt_context.banks_client;
    let payer = pt_context.payer;
    let recent_blockhash = pt_context.last_blockhash;
    let mut test_context = TestContext {
        program_id,
        banks_client,
        rent,
        payer,
        recent_blockhash,
    };
    assert_eq!(
        utils::init_wallet_config_policy_update(
            &mut test_context,
            wallet_account.pubkey(),
            &approvers[0],
            &update,
        )
        .await
        .unwrap_err()
        .unwrap(),
        TransactionError::InstructionError(1, Custom(WalletError::AccountVersionMismatch as u32))
    );
}
