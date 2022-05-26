#![cfg(feature = "test-bpf")]

mod common;

pub use common::instructions::*;
pub use common::utils;
pub use common::utils::*;

use solana_program::instruction::InstructionError::Custom;
use solana_program_test::tokio;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer as SdkSigner;
use std::time::{Duration, SystemTime};
use strike_wallet::error::WalletError;
use strike_wallet::instruction::{InitialWalletConfig, WalletConfigPolicyUpdate};
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, MultisigOpParams, OperationDisposition,
};
use strike_wallet::model::wallet::{Approvers, WalletGuidHash};
use strike_wallet::utils::SlotId;
use uuid::Uuid;

#[tokio::test]
async fn wallet_config_policy_update() {
    let started_at = SystemTime::now();
    let mut context = setup_test(40_000).await;

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

    let wallet = get_wallet(&mut context.banks_client, &wallet_account.pubkey()).await;

    let update = WalletConfigPolicyUpdate {
        approvals_required_for_config: 1,
        approval_timeout_for_config: Duration::from_secs(7200),
        config_approvers: vec![SlotId::new(1), SlotId::new(2)],
        signers_hash: hash_signers(&vec![signers[1], signers[2]]),
    };

    let multisig_op_account = utils::init_wallet_config_policy_update(
        &mut context,
        wallet_account.pubkey(),
        &approvers[2],
        &update,
    )
    .await
    .unwrap();

    assert_initialized_multisig_op(
        &get_multisig_op_data(&mut context.banks_client, multisig_op_account).await,
        started_at,
        Duration::from_secs(3600),
        2,
        &vec![
            ApprovalDispositionRecord {
                approver: approvers[0].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
            ApprovalDispositionRecord {
                approver: approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ],
        OperationDisposition::NONE,
        &MultisigOpParams::UpdateWalletConfigPolicy {
            wallet_address: wallet_account.pubkey(),
            update: update.clone(),
        },
        &approvers[2].pubkey(),
        &context.payer.pubkey(),
    );

    approve_n_of_n_multisig_op(
        &mut context,
        &multisig_op_account,
        vec![&approvers[0], &approvers[1]],
    )
    .await;

    utils::finalize_wallet_config_policy_update(
        &mut context,
        wallet_account.pubkey(),
        multisig_op_account,
        &update.clone(),
    )
    .await;

    let mut expected_wallet = wallet.clone();
    expected_wallet.approvals_required_for_config = 1;
    expected_wallet.approval_timeout_for_config = Duration::from_secs(7200);
    expected_wallet.config_approvers =
        Approvers::from_enabled_vec(vec![SlotId::new(1), SlotId::new(2)]);

    assert_eq!(
        expected_wallet,
        get_wallet(&mut context.banks_client, &wallet_account.pubkey()).await
    );

    // verify updates
    expected_wallet.approvals_required_for_config = 2;
    expected_wallet.approval_timeout_for_config = Duration::from_secs(14400);
    expected_wallet.config_approvers =
        Approvers::from_enabled_vec(vec![SlotId::new(0), SlotId::new(1), SlotId::new(2)]);

    utils::update_wallet_config_policy(
        &mut context,
        wallet_account.pubkey(),
        &assistant_account,
        &WalletConfigPolicyUpdate {
            approvals_required_for_config: 2,
            approval_timeout_for_config: Duration::from_secs(14400),
            config_approvers: vec![SlotId::new(0), SlotId::new(1), SlotId::new(2)],
            signers_hash: hash_signers(&vec![signers[0], signers[1], signers[2]]),
        },
        vec![&approvers[1], &approvers[2]],
    )
    .await;

    assert_eq!(
        expected_wallet,
        get_wallet(&mut context.banks_client, &wallet_account.pubkey()).await
    );

    expected_wallet.config_approvers =
        Approvers::from_enabled_vec(vec![SlotId::new(0), SlotId::new(1)]);

    utils::update_wallet_config_policy(
        &mut context,
        wallet_account.pubkey(),
        &assistant_account,
        &WalletConfigPolicyUpdate {
            approvals_required_for_config: 2,
            approval_timeout_for_config: Duration::from_secs(14400),
            config_approvers: vec![SlotId::new(0), SlotId::new(1)],
            signers_hash: hash_signers(&vec![signers[0], signers[1]]),
        },
        vec![&approvers[0], &approvers[1], &approvers[2]],
    )
    .await;

    assert_eq!(
        expected_wallet,
        get_wallet(&mut context.banks_client, &wallet_account.pubkey()).await
    );
}

#[tokio::test]
async fn invalid_wallet_config_policy_updates() {
    let mut context = setup_test(40_000).await;

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
            signers: vec![(SlotId::new(0), signers[0]), (SlotId::new(1), signers[1])],
            config_approvers: vec![SlotId::new(0), SlotId::new(1)],
        },
    )
    .await
    .unwrap();

    // verify approvals required for config can't exceed configured approvers count
    assert_instruction_error(
        utils::init_wallet_config_policy_update(
            &mut context,
            wallet_account.pubkey(),
            &assistant_account,
            &WalletConfigPolicyUpdate {
                approvals_required_for_config: 3,
                approval_timeout_for_config: Duration::from_secs(3200),
                config_approvers: vec![SlotId::new(0), SlotId::new(1)],
                signers_hash: hash_signers(&vec![signers[0], signers[1]]),
            },
        )
        .await,
        1,
        Custom(WalletError::InvalidApproverCount as u32),
    );

    // verify it's not allowed to add a config approver if signer slot is empty
    assert_instruction_error(
        utils::init_wallet_config_policy_update(
            &mut context,
            wallet_account.pubkey(),
            &assistant_account,
            &WalletConfigPolicyUpdate {
                approvals_required_for_config: 2,
                approval_timeout_for_config: Duration::from_secs(3200),
                config_approvers: vec![SlotId::new(0), SlotId::new(2)],
                signers_hash: hash_signers(&vec![signers[0], signers[2]]),
            },
        )
        .await,
        1,
        Custom(WalletError::UnknownSigner as u32),
    );

    // verify it's not allowed to add a config approver if signer in slot does not match signer.
    assert_instruction_error(
        utils::init_wallet_config_policy_update(
            &mut context,
            wallet_account.pubkey(),
            &assistant_account,
            &WalletConfigPolicyUpdate {
                approvals_required_for_config: 2,
                approval_timeout_for_config: Duration::from_secs(3200),
                config_approvers: vec![SlotId::new(0), SlotId::new(1)],
                signers_hash: hash_signers(&vec![signers[0], signers[2]]),
            },
        )
        .await,
        1,
        Custom(WalletError::InvalidSignersHash as u32),
    );
}

#[tokio::test]
async fn wallet_config_policy_update_initiator_approval() {
    let mut context = setup_test(30_000).await;

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

    let update = WalletConfigPolicyUpdate {
        approvals_required_for_config: 1,
        approval_timeout_for_config: Duration::from_secs(3600),
        config_approvers: vec![SlotId::new(0)],
        signers_hash: hash_signers(&vec![signers[0]]),
    };

    let multisig_op_account = utils::init_wallet_config_policy_update(
        &mut context,
        wallet_account.pubkey(),
        &approvers[0],
        &update.clone(),
    )
    .await
    .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(&mut context.banks_client, multisig_op_account).await,
        2,
        &vec![
            ApprovalDispositionRecord {
                approver: approvers[0].pubkey(),
                disposition: ApprovalDisposition::APPROVE,
            },
            ApprovalDispositionRecord {
                approver: approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ],
        OperationDisposition::NONE,
    );

    approve_n_of_n_multisig_op(
        &mut context,
        &multisig_op_account,
        vec![&approvers[0], &approvers[1]],
    )
    .await;

    utils::finalize_wallet_config_policy_update(
        &mut context,
        wallet_account.pubkey(),
        multisig_op_account,
        &update.clone(),
    )
    .await;

    let multisig_op_account = utils::init_wallet_config_policy_update(
        &mut context,
        wallet_account.pubkey(),
        &approvers[0],
        &WalletConfigPolicyUpdate {
            approvals_required_for_config: 1,
            approval_timeout_for_config: Duration::from_secs(7200),
            config_approvers: vec![SlotId::new(0)],
            signers_hash: hash_signers(&vec![signers[0]]),
        },
    )
    .await
    .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(&mut context.banks_client, multisig_op_account).await,
        1,
        &vec![ApprovalDispositionRecord {
            approver: approvers[0].pubkey(),
            disposition: ApprovalDisposition::APPROVE,
        }],
        OperationDisposition::APPROVED,
    );
}
