#![cfg(feature = "test-bpf")]
mod common;
pub use common::instructions::*;
pub use common::utils::*;

pub use common::utils;
use solana_program_test::tokio;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer as SdkSigner;
use std::time::{Duration, SystemTime};
use strike_wallet::instruction::{DAppBookUpdate, InitialWalletConfig};
use strike_wallet::model::address_book::{DAppBookEntry, DAppBookEntryNameHash};
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, MultisigOpParams, OperationDisposition,
};
use strike_wallet::utils::{SlotId, Slots};

#[tokio::test]
async fn test_dapp_book_update() {
    let started_at = SystemTime::now();
    let mut context = setup_test(40_000).await;

    let wallet_account = Keypair::new();
    let assistant_account = Keypair::new();

    let approvers = vec![Keypair::new(), Keypair::new()];
    let signers = vec![
        approvers[0].pubkey_as_signer(),
        approvers[1].pubkey_as_signer(),
    ];

    utils::init_wallet(
        &mut context.banks_client,
        &context.payer,
        context.recent_blockhash,
        &context.program_id,
        &wallet_account,
        &assistant_account,
        InitialWalletConfig {
            approvals_required_for_config: 1,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers: vec![(SlotId::new(0), signers[0]), (SlotId::new(1), signers[1])],
            config_approvers: vec![SlotId::new(0)],
        },
    )
    .await
    .unwrap();

    // add a dapp to dapp book
    let dapp_program_id = Keypair::new().pubkey();
    let dapp_slot = (
        SlotId::new(0),
        DAppBookEntry {
            address: dapp_program_id,
            name_hash: DAppBookEntryNameHash::new(&hash_of(b"DApp Name")),
        },
    );

    let add_dapp = DAppBookUpdate {
        add_dapps: vec![dapp_slot],
        remove_dapps: vec![],
    };

    let multisig_op_account = utils::init_dapp_book_update(
        &mut context,
        wallet_account.pubkey(),
        &approvers[1],
        add_dapp.clone(),
    )
    .await
    .unwrap();

    assert_initialized_multisig_op(
        &get_multisig_op_data(&mut context.banks_client, multisig_op_account).await,
        started_at,
        Duration::from_secs(3600),
        1,
        &vec![ApprovalDispositionRecord {
            approver: approvers[0].pubkey(),
            disposition: ApprovalDisposition::NONE,
        }],
        OperationDisposition::NONE,
        &MultisigOpParams::UpdateDAppBook {
            wallet_address: wallet_account.pubkey(),
            update: add_dapp.clone(),
        },
    );

    approve_n_of_n_multisig_op(&mut context, &multisig_op_account, vec![&approvers[0]]).await;

    utils::finalize_dapp_book_update(
        &mut context,
        wallet_account.pubkey(),
        multisig_op_account,
        add_dapp.clone(),
    )
    .await;

    assert_eq!(
        Slots::from_vec(vec![dapp_slot]),
        get_wallet(&mut context.banks_client, &wallet_account.pubkey())
            .await
            .dapp_book
    );

    // now remove it
    let remove_dapp = DAppBookUpdate {
        add_dapps: vec![],
        remove_dapps: vec![dapp_slot],
    };

    let remove_multisig_op_account = utils::init_dapp_book_update(
        &mut context,
        wallet_account.pubkey(),
        &approvers[0],
        remove_dapp.clone(),
    )
    .await
    .unwrap();

    assert_initialized_multisig_op(
        &get_multisig_op_data(&mut context.banks_client, remove_multisig_op_account).await,
        started_at,
        Duration::from_secs(3600),
        1,
        &vec![ApprovalDispositionRecord {
            approver: approvers[0].pubkey(),
            disposition: ApprovalDisposition::APPROVE,
        }],
        OperationDisposition::APPROVED,
        &MultisigOpParams::UpdateDAppBook {
            wallet_address: wallet_account.pubkey(),
            update: remove_dapp.clone(),
        },
    );

    utils::finalize_dapp_book_update(
        &mut context,
        wallet_account.pubkey(),
        remove_multisig_op_account,
        remove_dapp.clone(),
    )
    .await;

    assert_eq!(
        Slots::new(),
        get_wallet(&mut context.banks_client, &wallet_account.pubkey())
            .await
            .dapp_book
    );
}

#[tokio::test]
async fn test_dapp_book_update_initiator_approval() {
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

    let multisig_op_account = utils::init_dapp_book_update(
        &mut context,
        wallet_account.pubkey(),
        &approvers[2],
        DAppBookUpdate {
            add_dapps: vec![(
                SlotId::new(0),
                DAppBookEntry {
                    address: Keypair::new().pubkey(),
                    name_hash: DAppBookEntryNameHash::new(&hash_of(b"DApp Name")),
                },
            )],
            remove_dapps: vec![],
        },
    )
    .await
    .unwrap();

    assert_multisig_op_dispositions(
        &get_multisig_op_data(&mut context.banks_client, multisig_op_account).await,
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
    );

    let multisig_op_account = utils::init_dapp_book_update(
        &mut context,
        wallet_account.pubkey(),
        &approvers[0],
        DAppBookUpdate {
            add_dapps: vec![(
                SlotId::new(0),
                DAppBookEntry {
                    address: Keypair::new().pubkey(),
                    name_hash: DAppBookEntryNameHash::new(&hash_of(b"DApp Name")),
                },
            )],
            remove_dapps: vec![],
        },
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
}
