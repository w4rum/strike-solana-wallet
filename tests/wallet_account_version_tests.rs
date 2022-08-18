#![cfg(feature = "test-bpf")]

use std::time::Duration;

use solana_program::instruction::InstructionError::Custom;
use solana_program::program_pack::Pack;
use solana_program_test::tokio;
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
use strike_wallet::utils::SlotId;

mod common;

#[tokio::test]
async fn test_wallet_account_version_mismatch() {
    let mut test_context = setup_test(25_000).await;

    let wallet_account = Keypair::new();

    let approvers = vec![Keypair::new()];
    let signers = vec![approvers[0].pubkey_as_signer()];

    utils::init_wallet_from_context(
        &mut test_context,
        &wallet_account,
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
        test_context
            .pt_context
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
    test_context
        .pt_context
        .set_account(&wallet_account.pubkey(), &wallet_account_shared_data);

    let update = WalletConfigPolicyUpdate {
        approvals_required_for_config: 1,
        approval_timeout_for_config: Duration::from_secs(7200),
        config_approvers: vec![SlotId::new(1)],
        signers_hash: hash_signers(&vec![signers[0]]),
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
