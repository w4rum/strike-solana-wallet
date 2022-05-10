use crate::common::instructions;
use crate::common::instructions::{
    finalize_account_settings_update, finalize_balance_account_name_update, finalize_update_signer,
    finalize_wallet_config_policy_update_instruction, init_account_settings_update,
    init_balance_account_creation_instruction, init_balance_account_name_update, init_transfer,
    init_wallet_config_policy_update_instruction, set_approval_disposition,
};
use crate::{
    finalize_address_book_update, finalize_balance_account_address_whitelist_update_instruction,
    finalize_balance_account_policy_update_instruction, init_address_book_update_instruction,
    init_balance_account_address_whitelist_update_instruction,
    init_balance_account_policy_update_instruction,
};
use arrayref::array_ref;
use itertools::Itertools;
use sha2::{Digest, Sha256};
use solana_program::bpf_loader_upgradeable::{create_buffer, write};
use solana_program::hash::hash;
use solana_program::instruction::{Instruction, InstructionError};
use solana_program::rent::Rent;
use solana_program::system_program;
use solana_program_test::{processor, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::account::ReadableAccount;
use solana_sdk::transaction::TransactionError;
use std::borrow::BorrowMut;
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use strike_wallet::instruction::{
    AddressBookUpdate, BalanceAccountAddressWhitelistUpdate, BalanceAccountCreation,
    BalanceAccountPolicyUpdate, DAppBookUpdate, InitialWalletConfig, WalletConfigPolicyUpdate,
};
use strike_wallet::model::address_book::{
    AddressBookEntry, AddressBookEntryNameHash, DAppBookEntry, DAppBookEntryNameHash,
};
use strike_wallet::model::balance_account::{
    BalanceAccount, BalanceAccountGuidHash, BalanceAccountNameHash,
};
use strike_wallet::model::multisig_op::{
    ApprovalDisposition, ApprovalDispositionRecord, BooleanSetting, MultisigOp, MultisigOpParams,
    OperationDisposition, SlotUpdateType, WrapDirection,
};
use strike_wallet::model::signer::Signer;
use strike_wallet::model::wallet::{Signers, WalletGuidHash};
use strike_wallet::utils::SlotId;
use strike_wallet::version::VERSION;
use uuid::Uuid;
use {
    solana_program::{program_pack::Pack, pubkey::Pubkey},
    solana_program_test::BanksClient,
    solana_sdk::{
        hash::Hash,
        signature::{Keypair, Signer as SdkSigner},
        system_instruction,
        transaction::Transaction,
    },
    strike_wallet::{model::wallet::Wallet, processor::Processor},
};

pub trait SignerKey {
    fn pubkey_as_signer(&self) -> Signer;
}
impl SignerKey for Keypair {
    fn pubkey_as_signer(&self) -> Signer {
        Signer::new(self.pubkey())
    }
}

pub trait ToSet<A> {
    fn to_set(&self) -> HashSet<A>;
}

impl<A: core::hash::Hash + Eq + Clone> ToSet<A> for Option<Vec<A>> {
    fn to_set(&self) -> HashSet<A> {
        match self {
            Some(items) => items.to_set(),
            None => HashSet::new(),
        }
    }
}

impl<A: core::hash::Hash + Eq + Clone> ToSet<A> for Vec<A> {
    fn to_set(&self) -> HashSet<A> {
        let mut set = HashSet::new();
        for item in self.iter() {
            set.insert(item.clone());
        }
        set
    }
}

pub struct TestContext {
    pub program_id: Pubkey,
    pub banks_client: BanksClient,
    pub rent: Rent,
    pub payer: Keypair,
    pub recent_blockhash: Hash,
}

pub async fn setup_test(max_compute_units: u64) -> TestContext {
    let program_id = Keypair::new().pubkey();
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(max_compute_units);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;
    let rent = banks_client.get_rent().await.unwrap();

    TestContext {
        program_id,
        banks_client,
        rent,
        payer,
        recent_blockhash,
    }
}

pub fn create_program_owned_account_instruction(
    test_context: &TestContext,
    account_address: &Pubkey,
    space: usize,
) -> Instruction {
    system_instruction::create_account(
        &test_context.payer.pubkey(),
        &account_address,
        test_context.rent.minimum_balance(space),
        space as u64,
        &test_context.program_id,
    )
}

pub async fn init_multisig_op(
    test_context: &mut TestContext,
    multisig_op_account: Keypair,
    instruction: Instruction,
    initiator_account: &Keypair,
) -> Result<(), BanksClientError> {
    test_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[
                create_program_owned_account_instruction(
                    &test_context,
                    &multisig_op_account.pubkey(),
                    MultisigOp::LEN,
                ),
                instruction,
            ],
            Some(&test_context.payer.pubkey()),
            &[&test_context.payer, &multisig_op_account, initiator_account],
            test_context.recent_blockhash,
        ))
        .await
}

pub async fn finalize_multisig_op(
    test_context: &mut TestContext,
    multisig_op_account: Pubkey,
    instruction: Instruction,
) {
    let starting_rent_collector_balance = test_context
        .banks_client
        .get_balance(test_context.payer.pubkey())
        .await
        .unwrap();

    let op_account_balance = test_context
        .banks_client
        .get_balance(multisig_op_account)
        .await
        .unwrap();

    test_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[instruction],
            Some(&test_context.payer.pubkey()),
            &[&test_context.payer],
            test_context.recent_blockhash,
        ))
        .await
        .unwrap();

    // verify the multisig op account is closed
    assert!(test_context
        .banks_client
        .get_account(multisig_op_account)
        .await
        .unwrap()
        .is_none());

    // and that the remaining balance went to the rent collector (less the 5000 in fees for the finalize)
    let ending_rent_collector_balance = test_context
        .banks_client
        .get_balance(test_context.payer.pubkey())
        .await
        .unwrap();

    assert_eq!(
        starting_rent_collector_balance + op_account_balance - 5000,
        ending_rent_collector_balance
    );
}

pub async fn get_multisig_op_data(
    banks_client: &mut BanksClient,
    account_address: Pubkey,
) -> MultisigOp {
    return MultisigOp::unpack_from_slice(
        banks_client
            .get_account(account_address)
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();
}

pub async fn init_wallet_config_policy_update(
    test_context: &mut TestContext,
    wallet_account: Pubkey,
    initiator: &Keypair,
    update: &WalletConfigPolicyUpdate,
) -> Result<Pubkey, BanksClientError> {
    let multisig_op_keypair = Keypair::new();
    let multisig_op_pubkey = multisig_op_keypair.pubkey();

    let instruction = init_wallet_config_policy_update_instruction(
        test_context.program_id,
        wallet_account,
        multisig_op_pubkey,
        initiator.pubkey(),
        update,
    );

    init_multisig_op(test_context, multisig_op_keypair, instruction, initiator)
        .await
        .map(|_| multisig_op_pubkey)
}

pub async fn finalize_wallet_config_policy_update(
    test_context: &mut TestContext,
    wallet_account: Pubkey,
    multisig_op_account: Pubkey,
    update: &WalletConfigPolicyUpdate,
) {
    finalize_multisig_op(
        test_context,
        multisig_op_account,
        finalize_wallet_config_policy_update_instruction(
            test_context.program_id,
            wallet_account,
            multisig_op_account,
            test_context.payer.pubkey(),
            update,
        ),
    )
    .await;
}

pub async fn update_wallet_config_policy(
    test_context: &mut TestContext,
    wallet_account: Pubkey,
    initiator_account: &Keypair,
    update: &WalletConfigPolicyUpdate,
    approvers: Vec<&Keypair>,
) {
    let multisig_op_account =
        init_wallet_config_policy_update(test_context, wallet_account, &initiator_account, &update)
            .await
            .unwrap();

    approve_n_of_n_multisig_op(test_context, &multisig_op_account, approvers).await;

    finalize_wallet_config_policy_update(
        test_context,
        wallet_account,
        multisig_op_account,
        &update.clone(),
    )
    .await;
}

pub fn assert_instruction_error<R: Debug>(
    res: Result<R, BanksClientError>,
    expected_instruction_index: u8,
    expected_error: InstructionError,
) {
    assert_eq!(
        res.unwrap_err().unwrap(),
        TransactionError::InstructionError(expected_instruction_index, expected_error)
    );
}

pub async fn init_wallet(
    banks_client: &mut BanksClient,
    payer: &Keypair,
    recent_blockhash: Hash,
    program_id: &Pubkey,
    wallet_account: &Keypair,
    assistant_account: &Keypair,
    wallet_guid_hash: WalletGuidHash,
    initial_config: InitialWalletConfig,
) -> Result<(), BanksClientError> {
    let rent = banks_client.get_rent().await.unwrap();
    let program_rent = rent.minimum_balance(Wallet::LEN);

    let transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &wallet_account.pubkey(),
                program_rent,
                Wallet::LEN as u64,
                &program_id,
            ),
            instructions::init_wallet(
                &program_id,
                &wallet_account.pubkey(),
                &assistant_account.pubkey(),
                &payer.pubkey(),
                wallet_guid_hash,
                initial_config,
            ),
        ],
        Some(&payer.pubkey()),
        &[payer, wallet_account, assistant_account],
        recent_blockhash,
    );
    banks_client.process_transaction(transaction).await?;
    Ok(())
}

pub struct WalletTestContext {
    pub payer: Keypair,
    pub program_id: Pubkey,
    pub banks_client: BanksClient,
    pub rent: Rent,
    pub wallet_account: Keypair,
    pub assistant_account: Keypair,
    pub recent_blockhash: Hash,
    pub wallet_guid_hash: WalletGuidHash,
}

pub async fn setup_wallet_test(
    max_compute_units: u64,
    initial_config: InitialWalletConfig,
) -> WalletTestContext {
    let program_id = Keypair::new().pubkey();
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(max_compute_units);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;
    let rent = banks_client.get_rent().await.unwrap();

    let mut context = WalletTestContext {
        program_id,
        banks_client,
        rent,
        payer,
        recent_blockhash,
        wallet_account: Keypair::new(),
        assistant_account: Keypair::new(),
        wallet_guid_hash: WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
    };

    init_wallet(
        &mut context.banks_client,
        &context.payer,
        context.recent_blockhash,
        &context.program_id,
        &context.wallet_account,
        &context.assistant_account,
        context.wallet_guid_hash,
        InitialWalletConfig {
            approvals_required_for_config: initial_config.approvals_required_for_config,
            approval_timeout_for_config: initial_config.approval_timeout_for_config,
            signers: initial_config.signers,
            config_approvers: initial_config.config_approvers,
        },
    )
    .await
    .unwrap();

    return context;
}

pub async fn init_update_signer(
    context: &mut WalletTestContext,
    initiator_account: &Keypair,
    slot_update_type: SlotUpdateType,
    slot_id: usize,
    signer: Signer,
) -> Result<Pubkey, BanksClientError> {
    let rent = context.banks_client.get_rent().await.unwrap();
    let multisig_op_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let multisig_op_pubkey = multisig_op_account.pubkey();

    let init_transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.payer.pubkey(),
                &multisig_op_pubkey,
                multisig_op_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            instructions::init_update_signer(
                &context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_pubkey,
                &initiator_account.pubkey(),
                slot_update_type,
                SlotId::new(slot_id),
                signer,
            ),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer, &multisig_op_account, &initiator_account],
        context.recent_blockhash,
    );
    context
        .banks_client
        .process_transaction(init_transaction)
        .await
        .map(|_| multisig_op_pubkey)
}

pub async fn update_signer(
    context: &mut WalletTestContext,
    approvers: Vec<&Keypair>,
    slot_update_type: SlotUpdateType,
    slot_id: usize,
    signer: Signer,
    expected_signers: Option<Signers>,
    expected_error: Option<InstructionError>,
) {
    let init_multisig_op_result =
        init_update_signer(context, approvers[0], slot_update_type, slot_id, signer).await;

    let multisig_op_account = match expected_error {
        None => init_multisig_op_result.unwrap(),
        Some(error) => {
            assert_eq!(
                init_multisig_op_result.unwrap_err().unwrap(),
                TransactionError::InstructionError(1, error),
            );
            return;
        }
    };

    // verify the multisig op account data
    let multisig_op = MultisigOp::unpack_from_slice(
        context
            .banks_client
            .get_account(multisig_op_account)
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();
    assert!(multisig_op.is_initialized);
    assert_eq!(
        multisig_op.disposition_records.to_set(),
        HashSet::from([
            ApprovalDispositionRecord {
                approver: approvers[0].pubkey(),
                disposition: ApprovalDisposition::APPROVE,
            },
            ApprovalDispositionRecord {
                approver: approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ])
    );
    assert_eq!(multisig_op.dispositions_required, 2);
    assert_eq!(
        multisig_op.operation_disposition,
        OperationDisposition::NONE
    );

    assert_eq!(
        multisig_op.params_hash.unwrap(),
        MultisigOpParams::UpdateSigner {
            wallet_address: context.wallet_account.pubkey(),
            slot_update_type,
            slot_id: SlotId::new(slot_id),
            signer
        }
        .hash()
    );

    approve_or_deny_n_of_n_multisig_op(
        context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account,
        approvers,
        &context.payer,
        context.recent_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // verify the multisig op account data
    let multisig_op = MultisigOp::unpack_from_slice(
        context
            .banks_client
            .get_account(multisig_op_account)
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();
    assert_eq!(
        multisig_op.operation_disposition,
        OperationDisposition::APPROVED
    );

    // finalize the multisig op
    let finalize_transaction = Transaction::new_signed_with_payer(
        &[finalize_update_signer(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &multisig_op_account,
            &context.payer.pubkey(),
            slot_update_type,
            SlotId::new(slot_id),
            signer,
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.recent_blockhash,
    );
    let starting_rent_collector_balance = context
        .banks_client
        .get_balance(context.payer.pubkey())
        .await
        .unwrap();
    let op_account_balance = context
        .banks_client
        .get_balance(multisig_op_account)
        .await
        .unwrap();
    context
        .banks_client
        .process_transaction(finalize_transaction)
        .await
        .unwrap();

    // verify the config has been updated
    let wallet = get_wallet(&mut context.banks_client, &context.wallet_account.pubkey()).await;
    assert_eq!(expected_signers.unwrap(), wallet.signers);

    // verify the multisig op account is closed
    assert!(context
        .banks_client
        .get_account(multisig_op_account)
        .await
        .unwrap()
        .is_none());
    // and that the remaining balance went to the rent collector (less the 5000 in fees for the finalize)
    let ending_rent_collector_balance = context
        .banks_client
        .get_balance(context.payer.pubkey())
        .await
        .unwrap();
    assert_eq!(
        starting_rent_collector_balance + op_account_balance - 5000,
        ending_rent_collector_balance
    );
}

pub async fn account_settings_update(
    context: &mut BalanceAccountTestContext,
    whitelist_status: Option<BooleanSetting>,
    dapps_enabled: Option<BooleanSetting>,
    expected_error: Option<InstructionError>,
) {
    let rent = context.pt_context.banks_client.get_rent().await.unwrap();
    let multisig_op_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let init_transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.pt_context.payer.pubkey(),
                &multisig_op_account.pubkey(),
                multisig_op_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            init_account_settings_update(
                &context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &context.approvers[0].pubkey(),
                context.balance_account_guid_hash,
                whitelist_status,
                dapps_enabled,
            ),
        ],
        Some(&context.pt_context.payer.pubkey()),
        &[
            &context.pt_context.payer,
            &multisig_op_account,
            &context.approvers[0],
        ],
        context.pt_context.last_blockhash,
    );
    match expected_error {
        None => context
            .pt_context
            .banks_client
            .process_transaction(init_transaction)
            .await
            .unwrap(),
        Some(error) => {
            assert_eq!(
                context
                    .pt_context
                    .banks_client
                    .process_transaction(init_transaction)
                    .await
                    .unwrap_err()
                    .unwrap(),
                TransactionError::InstructionError(1, error),
            );
            return;
        }
    }

    // verify the multisig op account data
    let multisig_op = MultisigOp::unpack_from_slice(
        context
            .pt_context
            .banks_client
            .get_account(multisig_op_account.pubkey())
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();
    assert!(multisig_op.is_initialized);
    assert_eq!(
        multisig_op.disposition_records.to_set(),
        HashSet::from([
            ApprovalDispositionRecord {
                approver: context.approvers[0].pubkey(),
                disposition: ApprovalDisposition::APPROVE,
            },
            ApprovalDispositionRecord {
                approver: context.approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ])
    );
    assert_eq!(multisig_op.dispositions_required, 2);
    assert_eq!(
        multisig_op.operation_disposition,
        OperationDisposition::NONE
    );

    assert_eq!(
        multisig_op.params_hash.unwrap(),
        MultisigOpParams::UpdateBalanceAccountSettings {
            wallet_address: context.wallet_account.pubkey(),
            account_guid_hash: context.balance_account_guid_hash,
            whitelist_enabled: whitelist_status,
            dapps_enabled,
        }
        .hash()
    );

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account.pubkey(),
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // finalize the multisig op
    let finalize_transaction = Transaction::new_signed_with_payer(
        &[finalize_account_settings_update(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &multisig_op_account.pubkey(),
            &context.pt_context.payer.pubkey(),
            context.balance_account_guid_hash,
            whitelist_status,
            dapps_enabled,
        )],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );

    let starting_rent_collector_balance = context
        .pt_context
        .banks_client
        .get_balance(context.pt_context.payer.pubkey())
        .await
        .unwrap();
    let op_account_balance = context
        .pt_context
        .banks_client
        .get_balance(multisig_op_account.pubkey())
        .await
        .unwrap();
    context
        .pt_context
        .banks_client
        .process_transaction(finalize_transaction)
        .await
        .unwrap();

    // verify the multisig op account is closed
    assert!(context
        .pt_context
        .banks_client
        .get_account(multisig_op_account.pubkey())
        .await
        .unwrap()
        .is_none());
    // and that the remaining balance went to the rent collector (less the 5000 in fees for the finalize)
    let ending_rent_collector_balance = context
        .pt_context
        .banks_client
        .get_balance(context.pt_context.payer.pubkey())
        .await
        .unwrap();
    assert_eq!(
        starting_rent_collector_balance + op_account_balance - 5000,
        ending_rent_collector_balance
    );
}

pub async fn init_dapp_book_update(
    test_context: &mut TestContext,
    wallet_account: Pubkey,
    initiator: &Keypair,
    update: DAppBookUpdate,
) -> Result<Pubkey, BanksClientError> {
    let multisig_op_keypair = Keypair::new();
    let multisig_op_pubkey = multisig_op_keypair.pubkey();

    let instruction = instructions::init_dapp_book_update(
        &test_context.program_id,
        &wallet_account,
        &multisig_op_pubkey,
        &initiator.pubkey(),
        update,
    );

    init_multisig_op(test_context, multisig_op_keypair, instruction, initiator)
        .await
        .map(|_| multisig_op_pubkey)
}

pub async fn finalize_dapp_book_update(
    test_context: &mut TestContext,
    wallet_account: Pubkey,
    multisig_op_account: Pubkey,
    update: DAppBookUpdate,
) {
    finalize_multisig_op(
        test_context,
        multisig_op_account,
        instructions::finalize_dapp_book_update(
            &test_context.program_id,
            &wallet_account,
            &multisig_op_account,
            &test_context.payer.pubkey(),
            update,
        ),
    )
    .await;
}

pub async fn verify_whitelist_status(
    context: &mut BalanceAccountTestContext,
    expected_status: BooleanSetting,
    expected_whitelist_count: usize,
) {
    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;
    let account = wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();

    assert_eq!(account.whitelist_enabled, expected_status);
    assert_eq!(
        account.allowed_destinations.count_enabled(),
        expected_whitelist_count
    );
}

pub async fn verify_dapps_enabled(
    context: &mut BalanceAccountTestContext,
    expected_enabled: BooleanSetting,
) {
    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;
    let account = wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();

    assert_eq!(account.dapps_enabled, expected_enabled);
}

pub async fn verify_balance_account_name_hash(
    context: &mut BalanceAccountTestContext,
    expected_name_hash: &BalanceAccountNameHash,
) {
    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;
    let account = wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();

    assert_eq!(account.name_hash, *expected_name_hash);

    // make sure address book entry has the new name
    let (source_account, _) = Pubkey::find_program_address(
        &[
            context.wallet_guid_hash.to_bytes(),
            context.balance_account_guid_hash.to_bytes(),
        ],
        &context.program_id,
    );
    let entry = wallet
        .get_address_book_entry_with_slot_id(&source_account)
        .unwrap();
    assert_eq!(
        entry.1.name_hash,
        AddressBookEntryNameHash::new(expected_name_hash.to_bytes())
    )
}

pub async fn approve_or_deny_n_of_n_multisig_op(
    banks_client: &mut BanksClient,
    program_id: &Pubkey,
    multisig_op_account: &Pubkey,
    approvers: Vec<&Keypair>,
    payer: &Keypair,
    recent_blockhash: Hash,
    disposition: ApprovalDisposition,
    expected_operation_disposition: OperationDisposition,
) {
    let params_hash = get_operation_hash(banks_client.borrow_mut(), *multisig_op_account).await;

    // approve the config change
    for approver in approvers.iter() {
        let approve_transaction = Transaction::new_signed_with_payer(
            &[set_approval_disposition(
                program_id,
                multisig_op_account,
                &approver.pubkey(),
                disposition,
                params_hash,
            )],
            Some(&payer.pubkey()),
            &[payer, approver],
            recent_blockhash,
        );
        banks_client
            .process_transaction(approve_transaction)
            .await
            .unwrap();
    }

    // verify the disposition was recorded in the multisig op account
    let multisig_op = MultisigOp::unpack_from_slice(
        banks_client
            .get_account(*multisig_op_account)
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();
    assert_eq!(
        multisig_op.disposition_records.to_set(),
        approvers
            .iter()
            .map(|approver| ApprovalDispositionRecord {
                approver: approver.pubkey(),
                disposition,
            })
            .collect_vec()
            .to_set()
    );
    assert_eq!(
        multisig_op.operation_disposition,
        expected_operation_disposition
    )
}

pub async fn approve_n_of_n_multisig_op(
    test_context: &mut TestContext,
    multisig_op_account: &Pubkey,
    approvers: Vec<&Keypair>,
) {
    approve_or_deny_n_of_n_multisig_op(
        &mut test_context.banks_client,
        &test_context.program_id,
        &multisig_op_account,
        approvers,
        &test_context.payer,
        test_context.recent_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;
}

pub async fn deny_n_of_n_multisig_op(
    test_context: &mut TestContext,
    multisig_op_account: &Pubkey,
    approvers: Vec<&Keypair>,
) {
    approve_or_deny_n_of_n_multisig_op(
        &mut test_context.banks_client,
        &test_context.program_id,
        &multisig_op_account,
        approvers,
        &test_context.payer,
        test_context.recent_blockhash,
        ApprovalDisposition::DENY,
        OperationDisposition::DENIED,
    )
    .await;
}

pub async fn approve_or_deny_1_of_2_multisig_op(
    banks_client: &mut BanksClient,
    program_id: &Pubkey,
    multisig_op_account: &Pubkey,
    approver: &Keypair,
    payer: &Keypair,
    other_approver: &Pubkey,
    recent_blockhash: Hash,
    disposition: ApprovalDisposition,
) {
    let params_hash = get_operation_hash(banks_client.borrow_mut(), *multisig_op_account).await;

    // approve the config change
    let approve_transaction = Transaction::new_signed_with_payer(
        &[set_approval_disposition(
            program_id,
            multisig_op_account,
            &approver.pubkey(),
            disposition,
            params_hash,
        )],
        Some(&payer.pubkey()),
        &[payer, approver],
        recent_blockhash,
    );
    banks_client
        .process_transaction(approve_transaction)
        .await
        .unwrap();

    // verify the disposition was recorded in the multisig op account
    let multisig_op = MultisigOp::unpack_from_slice(
        banks_client
            .get_account(*multisig_op_account)
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();
    assert_eq!(
        multisig_op.disposition_records.to_set(),
        HashSet::from([
            ApprovalDispositionRecord {
                approver: approver.pubkey(),
                disposition,
            },
            ApprovalDispositionRecord {
                approver: *other_approver,
                disposition: ApprovalDisposition::NONE,
            },
        ])
    );
}

pub fn hash_of(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash_output = hasher.finalize();
    *array_ref![hash_output, 0, 32]
}

pub struct BalanceAccountTestContext {
    pub program_id: Pubkey,
    pub pt_context: ProgramTestContext,
    pub rent: Rent,
    pub wallet_account: Keypair,
    pub wallet_guid_hash: WalletGuidHash,
    pub multisig_op_account: Keypair,
    pub assistant_account: Keypair,
    pub initiator_account: Keypair,
    pub approvers: Vec<Keypair>,
    pub expected_creation_params: BalanceAccountCreation,
    pub balance_account_name_hash: BalanceAccountNameHash,
    pub balance_account_guid_hash: BalanceAccountGuidHash,
    pub balance_account_address_book_entry: (SlotId<AddressBookEntry>, AddressBookEntry),
    pub destination_name_hash: AddressBookEntryNameHash,
    pub allowed_destination: AddressBookEntry,
    pub destination: Keypair,
    pub params_hash: Hash,
    pub allowed_dapp: DAppBookEntry,
}

impl BalanceAccountTestContext {
    fn to_test_context(&self) -> TestContext {
        let new_payer = Keypair::from_bytes(&self.pt_context.payer.to_bytes()[..]).unwrap();
        TestContext {
            program_id: self.program_id,
            banks_client: self.pt_context.banks_client.clone(),
            rent: self.rent,
            payer: new_payer,
            recent_blockhash: self.pt_context.last_blockhash,
        }
    }
}

pub async fn init_balance_account_creation(
    context: &mut WalletTestContext,
    initiator_account: &Keypair,
    balance_account_guid_hash: BalanceAccountGuidHash,
    creation_params: BalanceAccountCreation,
) -> Result<Pubkey, BanksClientError> {
    let rent = context.banks_client.get_rent().await.unwrap();
    let multisig_op_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let multisig_op_pubkey = multisig_op_account.pubkey();

    let init_transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.payer.pubkey(),
                &multisig_op_account.pubkey(),
                multisig_op_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            init_balance_account_creation_instruction(
                &context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &initiator_account.pubkey(),
                creation_params.slot_id,
                balance_account_guid_hash,
                creation_params.name_hash,
                creation_params.approvals_required_for_transfer,
                creation_params.approval_timeout_for_transfer,
                creation_params.transfer_approvers.clone(),
                creation_params.signers_hash,
                creation_params.whitelist_enabled,
                creation_params.dapps_enabled,
                creation_params.address_book_slot_id,
            ),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer, &multisig_op_account, &initiator_account],
        context.recent_blockhash,
    );

    context
        .banks_client
        .process_transaction(init_transaction)
        .await
        .map(|_| multisig_op_pubkey)
}

pub async fn setup_balance_account_tests(
    compute_max_units: Option<u64>,
    add_extra_transfer_approver: bool,
) -> BalanceAccountTestContext {
    let program_id = Keypair::new().pubkey();
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(compute_max_units.unwrap_or(50_000));
    let mut pt_context = pt.start_with_context().await;
    let wallet_account = Keypair::new();
    let multisig_op_account = Keypair::new();
    let assistant_account = Keypair::new();

    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];

    let destination = Keypair::new();
    let addr_book_entry = AddressBookEntry {
        address: destination.pubkey(),
        name_hash: AddressBookEntryNameHash::new(&hash_of(b"Destination 1 Name")),
    };
    let allowed_dapp = DAppBookEntry {
        address: Keypair::new().pubkey(),
        name_hash: DAppBookEntryNameHash::new(&hash_of(b"DApp Name")),
    };

    let wallet_guid_hash = WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes()));

    // first initialize the wallet
    init_wallet(
        &mut pt_context.banks_client,
        &pt_context.payer,
        pt_context.last_blockhash,
        &program_id,
        &wallet_account,
        &assistant_account,
        wallet_guid_hash,
        InitialWalletConfig {
            approvals_required_for_config: 2,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers: vec![
                (SlotId::new(0), approvers[0].pubkey_as_signer()),
                (SlotId::new(1), approvers[1].pubkey_as_signer()),
                (SlotId::new(2), approvers[2].pubkey_as_signer()),
            ],
            config_approvers: vec![SlotId::new(0), SlotId::new(1)],
        },
    )
    .await
    .unwrap();

    // now initialize balance account creation
    let rent = pt_context.banks_client.get_rent().await.unwrap();
    let multisig_account_rent = rent.minimum_balance(MultisigOp::LEN);
    let balance_account_guid_hash =
        BalanceAccountGuidHash::new(&hash_of(Uuid::new_v4().as_bytes()));
    let balance_account_name_hash = BalanceAccountNameHash::new(&hash_of(b"Account Name"));
    let approval_timeout_for_transfer = Duration::from_secs(120);

    let mut transfer_approvers = vec![
        (SlotId::new(0), approvers[0].pubkey_as_signer()),
        (SlotId::new(1), approvers[1].pubkey_as_signer()),
    ];
    if add_extra_transfer_approver {
        transfer_approvers.append(&mut vec![(SlotId::new(2), approvers[2].pubkey_as_signer())])
    }

    let slot_for_balance_account_address = SlotId::new(32);
    let (source_account_pda, _) = Pubkey::find_program_address(
        &[
            wallet_guid_hash.to_bytes(),
            balance_account_guid_hash.to_bytes(),
        ],
        &program_id,
    );

    let init_transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &pt_context.payer.pubkey(),
                &multisig_op_account.pubkey(),
                multisig_account_rent,
                MultisigOp::LEN as u64,
                &program_id,
            ),
            init_balance_account_creation_instruction(
                &program_id,
                &wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &approvers[2].pubkey(),
                SlotId::new(0),
                balance_account_guid_hash,
                balance_account_name_hash,
                2,
                approval_timeout_for_transfer,
                transfer_approvers
                    .clone()
                    .iter()
                    .map(|approver| approver.0)
                    .collect_vec(),
                hash_signers(
                    &transfer_approvers
                        .clone()
                        .iter()
                        .map(|approver| approver.1)
                        .collect_vec(),
                ),
                BooleanSetting::Off,
                BooleanSetting::Off,
                slot_for_balance_account_address,
            ),
        ],
        Some(&pt_context.payer.pubkey()),
        &[&pt_context.payer, &multisig_op_account, &approvers[2]],
        pt_context.last_blockhash,
    );
    pt_context
        .banks_client
        .process_transaction(init_transaction)
        .await
        .unwrap();

    // verify the multisig op account data
    let multisig_op = MultisigOp::unpack_from_slice(
        pt_context
            .banks_client
            .get_account(multisig_op_account.pubkey())
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();
    assert!(multisig_op.is_initialized);
    assert_eq!(
        multisig_op.disposition_records.to_set(),
        HashSet::from([
            ApprovalDispositionRecord {
                approver: approvers[0].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
            ApprovalDispositionRecord {
                approver: approvers[1].pubkey(),
                disposition: ApprovalDisposition::NONE,
            },
        ])
    );
    assert_eq!(multisig_op.dispositions_required, 2);
    assert_eq!(multisig_op.version, VERSION);

    let expected_creation_params = BalanceAccountCreation {
        slot_id: SlotId::new(0),
        name_hash: balance_account_name_hash,
        approvals_required_for_transfer: 2,
        approval_timeout_for_transfer,
        transfer_approvers: transfer_approvers
            .clone()
            .iter()
            .map(|approver| approver.0)
            .collect_vec(),
        signers_hash: hash_signers(
            &transfer_approvers
                .clone()
                .iter()
                .map(|approver| approver.1)
                .collect_vec(),
        ),
        whitelist_enabled: BooleanSetting::Off,
        dapps_enabled: BooleanSetting::Off,
        address_book_slot_id: SlotId::new(32),
    };

    assert_eq!(
        multisig_op.params_hash.unwrap(),
        MultisigOpParams::CreateBalanceAccount {
            wallet_address: wallet_account.pubkey(),
            account_guid_hash: balance_account_guid_hash,
            creation_params: expected_creation_params.clone(),
        }
        .hash()
    );

    BalanceAccountTestContext {
        program_id,
        pt_context,
        rent,
        wallet_account,
        wallet_guid_hash,
        multisig_op_account,
        assistant_account,
        initiator_account: Keypair::from_base58_string(&approvers[2].to_base58_string()),
        approvers,
        expected_creation_params,
        balance_account_name_hash,
        balance_account_guid_hash,
        balance_account_address_book_entry: (
            slot_for_balance_account_address,
            AddressBookEntry {
                address: source_account_pda,
                name_hash: AddressBookEntryNameHash::new(&hash_of(b"Account Name")),
            },
        ),
        destination_name_hash: addr_book_entry.name_hash,
        allowed_destination: addr_book_entry,
        destination,
        params_hash: multisig_op.params_hash.unwrap(),
        allowed_dapp,
    }
}

pub async fn get_operation_hash(banks_client: &mut BanksClient, op_address: Pubkey) -> Hash {
    let multisig_op = MultisigOp::unpack_from_slice(
        banks_client
            .get_account(op_address)
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap();

    multisig_op.params_hash.unwrap()
}

pub async fn setup_create_balance_account_failure_tests(
    bpf_compute_max_units: Option<u64>,
    approvals_required_for_transfer: u8,
    approval_timeout_for_transfer: Duration,
    transfer_approvers: Vec<Pubkey>,
) -> TransactionError {
    let program_id = Keypair::new().pubkey();
    let mut pt = ProgramTest::new("strike_wallet", program_id, processor!(Processor::process));
    pt.set_compute_max_units(bpf_compute_max_units.unwrap_or(25_000));
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;
    let wallet_account = Keypair::new();
    let multisig_op_account = Keypair::new();
    let assistant_account = Keypair::new();

    let approvers = vec![Keypair::new(), Keypair::new(), Keypair::new()];

    // add given transfer approvers to signers
    let mut signers = transfer_approvers
        .iter()
        .enumerate()
        .map(|(i, pk)| (SlotId::new(i), Signer::new(*pk)))
        .collect_vec();
    // add a couple random signers to ensure init wallet has a non-zero signers
    // vec in case the given transfer_approvers vec has insufficient length.
    approvers
        .iter()
        .for_each(|kp| signers.push((SlotId::new(signers.len()), kp.pubkey_as_signer())));

    // take the first two signers as config approvers
    let config_approvers = signers[..2].to_vec();

    // first initialize the wallet
    init_wallet(
        &mut banks_client,
        &payer,
        recent_blockhash,
        &program_id,
        &wallet_account,
        &assistant_account,
        WalletGuidHash::new(&hash_of(Uuid::new_v4().as_bytes())),
        InitialWalletConfig {
            approvals_required_for_config: 1,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers,
            config_approvers: vec![config_approvers[0].0, config_approvers[1].0], // take the first two signers as config approvers
        },
    )
    .await
    .unwrap();

    // now initialize a balance account creation
    let rent = banks_client.get_rent().await.unwrap();
    let multisig_account_rent = rent.minimum_balance(MultisigOp::LEN);
    let balance_account_guid_hash =
        BalanceAccountGuidHash::new(&hash_of(Uuid::new_v4().as_bytes()));
    let balance_account_name_hash = BalanceAccountNameHash::new(&hash_of(b"Account Name"));

    let init_transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &multisig_op_account.pubkey(),
                multisig_account_rent,
                MultisigOp::LEN as u64,
                &program_id,
            ),
            init_balance_account_creation_instruction(
                &program_id,
                &wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &assistant_account.pubkey(),
                SlotId::new(0),
                balance_account_guid_hash,
                balance_account_name_hash,
                approvals_required_for_transfer,
                approval_timeout_for_transfer,
                transfer_approvers
                    .iter()
                    .enumerate()
                    .map(|(i, _)| SlotId::new(i))
                    .collect_vec(),
                hash_signers(
                    &transfer_approvers
                        .iter()
                        .map(|pk| Signer::new(*pk))
                        .collect_vec(),
                ),
                BooleanSetting::Off,
                BooleanSetting::Off,
                SlotId::new(32),
            ),
        ],
        Some(&payer.pubkey()),
        &[&payer, &multisig_op_account, &assistant_account],
        recent_blockhash,
    );
    banks_client
        .process_transaction(init_transaction)
        .await
        .unwrap_err()
        .unwrap()
}

pub async fn finalize_balance_account_creation(context: &mut BalanceAccountTestContext) {
    let finalize_transaction = Transaction::new_signed_with_payer(
        &[instructions::finalize_balance_account_creation(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &context.multisig_op_account.pubkey(),
            &context.pt_context.payer.pubkey(),
            context.balance_account_guid_hash,
            context.expected_creation_params.clone(),
        )],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );
    context
        .pt_context
        .banks_client
        .process_transaction(finalize_transaction)
        .await
        .unwrap();
}

pub async fn setup_balance_account_tests_and_finalize(
    compute_max_units: Option<u64>,
) -> (BalanceAccountTestContext, Pubkey) {
    let mut context = setup_balance_account_tests(compute_max_units, false).await;

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &context.multisig_op_account.pubkey(),
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    finalize_balance_account_creation(context.borrow_mut()).await;
    let (source_account, _) = Pubkey::find_program_address(
        &[
            context.wallet_guid_hash.to_bytes(),
            context.balance_account_guid_hash.to_bytes(),
        ],
        &context.program_id,
    );

    let allowed_destination = context.allowed_destination.clone();
    modify_address_book(
        &mut context,
        vec![
            (SlotId::new(0), allowed_destination),
            (
                SlotId::new(1),
                AddressBookEntry {
                    address: Keypair::new().pubkey(),
                    name_hash: AddressBookEntryNameHash::new(&hash_of(b"Destination 2 Name")),
                },
            ),
        ],
        vec![],
        None,
    )
    .await;

    // add allowed dapp
    let mut test_context = context.to_test_context();
    let update = DAppBookUpdate {
        add_dapps: vec![(SlotId::new(0), context.allowed_dapp)],
        remove_dapps: vec![],
    };

    let multisig_op_account = init_dapp_book_update(
        &mut test_context,
        context.wallet_account.pubkey(),
        &context.assistant_account,
        update.clone(),
    )
    .await
    .unwrap();

    approve_n_of_n_multisig_op(
        &mut test_context,
        &multisig_op_account,
        vec![&context.approvers[0], &context.approvers[1]],
    )
    .await;

    finalize_dapp_book_update(
        &mut test_context,
        context.wallet_account.pubkey(),
        multisig_op_account,
        update.clone(),
    )
    .await;

    (context, source_account)
}

pub async fn setup_transfer_test(
    context: &mut BalanceAccountTestContext,
    initiator_account: &Keypair,
    balance_account: &Pubkey,
    token_mint: Option<&Pubkey>,
    amount: u64,
) -> (Keypair, Result<(), BanksClientError>) {
    let rent = context.pt_context.banks_client.get_rent().await.unwrap();
    let multisig_account_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let initialized_at = SystemTime::now();

    let result = context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[
                system_instruction::create_account(
                    &context.pt_context.payer.pubkey(),
                    &multisig_op_account.pubkey(),
                    multisig_account_rent,
                    MultisigOp::LEN as u64,
                    &context.program_id,
                ),
                init_transfer(
                    &context.program_id,
                    &context.wallet_account.pubkey(),
                    &multisig_op_account.pubkey(),
                    &initiator_account.pubkey(),
                    &balance_account,
                    &context.destination.pubkey(),
                    context.balance_account_guid_hash,
                    amount,
                    context.destination_name_hash,
                    token_mint.unwrap_or(&system_program::id()),
                    &context.pt_context.payer.pubkey(),
                ),
            ],
            Some(&context.pt_context.payer.pubkey()),
            &[
                &context.pt_context.payer,
                &multisig_op_account,
                &initiator_account,
            ],
            context.pt_context.last_blockhash,
        ))
        .await;

    if result.is_ok() {
        assert_multisig_op_timestamps(
            &get_multisig_op_data(
                &mut context.pt_context.banks_client,
                multisig_op_account.pubkey(),
            )
            .await,
            initialized_at,
            Duration::from_secs(120),
        );
    }

    (multisig_op_account, result)
}

pub async fn init_address_book_update(
    context: &mut BalanceAccountTestContext,
    initiator_account: &Keypair,
    update: AddressBookUpdate,
) -> Result<Pubkey, BanksClientError> {
    let rent = context.pt_context.banks_client.get_rent().await.unwrap();
    let multisig_op_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let multisig_op_pubkey = multisig_op_account.pubkey();

    let init_update_tx = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.pt_context.payer.pubkey(),
                &multisig_op_pubkey,
                multisig_op_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            init_address_book_update_instruction(
                &context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &initiator_account.pubkey(),
                update.add_address_book_entries,
                update.remove_address_book_entries,
                update.balance_account_whitelist_updates,
            ),
        ],
        Some(&context.pt_context.payer.pubkey()),
        &[
            &context.pt_context.payer,
            &multisig_op_account,
            &initiator_account,
        ],
        context.pt_context.last_blockhash,
    );

    context
        .pt_context
        .banks_client
        .process_transaction(init_update_tx)
        .await
        .map(|_| multisig_op_pubkey)
}

pub async fn init_balance_account_address_whitelist_update(
    context: &mut BalanceAccountTestContext,
    initiator_account: &Keypair,
    update: BalanceAccountAddressWhitelistUpdate,
) -> Result<Pubkey, BanksClientError> {
    let rent = context.pt_context.banks_client.get_rent().await.unwrap();
    let multisig_op_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let multisig_op_pubkey = multisig_op_account.pubkey();

    let init_update_tx = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.pt_context.payer.pubkey(),
                &multisig_op_pubkey,
                multisig_op_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            init_balance_account_address_whitelist_update_instruction(
                &context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &initiator_account.pubkey(),
                context.balance_account_guid_hash,
                update,
            ),
        ],
        Some(&context.pt_context.payer.pubkey()),
        &[
            &context.pt_context.payer,
            &multisig_op_account,
            &initiator_account,
        ],
        context.pt_context.last_blockhash,
    );

    context
        .pt_context
        .banks_client
        .process_transaction(init_update_tx)
        .await
        .map(|_| multisig_op_pubkey)
}

pub async fn modify_address_book(
    context: &mut BalanceAccountTestContext,
    entries_to_add: Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    entries_to_remove: Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    expected_error: Option<InstructionError>,
) {
    // add a whitelisted destination
    let initiator_account =
        Keypair::from_base58_string(&context.initiator_account.to_base58_string());

    let update = AddressBookUpdate {
        add_address_book_entries: entries_to_add.clone(),
        remove_address_book_entries: entries_to_remove.clone(),
        balance_account_whitelist_updates: vec![],
    };

    let init_result = init_address_book_update(context, &initiator_account, update.clone()).await;

    let multisig_op_account = match expected_error {
        None => init_result.unwrap(),
        Some(error) => {
            assert_eq!(
                init_result.unwrap_err().unwrap(),
                TransactionError::InstructionError(1, error),
            );
            return;
        }
    };

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account,
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // finalize the config update
    let finalize_update = Transaction::new_signed_with_payer(
        &[finalize_address_book_update(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &multisig_op_account,
            &context.pt_context.payer.pubkey(),
            update,
        )],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );
    context
        .pt_context
        .banks_client
        .process_transaction(finalize_update)
        .await
        .unwrap();
}

pub async fn modify_balance_account_address_whitelist(
    context: &mut BalanceAccountTestContext,
    whitelist_destinations: Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    expected_error: Option<InstructionError>,
) {
    // add a whitelisted destination
    let initiator_account =
        Keypair::from_base58_string(&context.initiator_account.to_base58_string());

    let update = BalanceAccountAddressWhitelistUpdate {
        allowed_destinations: whitelist_destinations
            .iter()
            .map(|destination| destination.0)
            .collect_vec(),
        destinations_hash: hash_allowed_destinations(&whitelist_destinations),
    };

    let init_result =
        init_balance_account_address_whitelist_update(context, &initiator_account, update.clone())
            .await;

    let multisig_op_account = match expected_error {
        None => init_result.unwrap(),
        Some(error) => {
            assert_eq!(
                init_result.unwrap_err().unwrap(),
                TransactionError::InstructionError(1, error),
            );
            return;
        }
    };

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account,
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // finalize the config update
    let finalize_update = Transaction::new_signed_with_payer(
        &[
            finalize_balance_account_address_whitelist_update_instruction(
                &context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account,
                &context.pt_context.payer.pubkey(),
                context.balance_account_guid_hash,
                update,
            ),
        ],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );
    context
        .pt_context
        .banks_client
        .process_transaction(finalize_update)
        .await
        .unwrap();
}

pub async fn init_balance_account_name_hash_update(
    context: &mut BalanceAccountTestContext,
    initiator_account: &Keypair,
    account_name_hash: BalanceAccountNameHash,
) -> Result<Pubkey, BanksClientError> {
    let rent = context.pt_context.banks_client.get_rent().await.unwrap();
    let multisig_op_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let multisig_op_pubkey = multisig_op_account.pubkey();

    let init_update_tx = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.pt_context.payer.pubkey(),
                &multisig_op_account.pubkey(),
                multisig_op_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            init_balance_account_name_update(
                &context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_account.pubkey(),
                &initiator_account.pubkey(),
                context.balance_account_guid_hash,
                account_name_hash,
            ),
        ],
        Some(&context.pt_context.payer.pubkey()),
        &[
            &context.pt_context.payer,
            &multisig_op_account,
            &initiator_account,
        ],
        context.pt_context.last_blockhash,
    );

    context
        .pt_context
        .banks_client
        .process_transaction(init_update_tx)
        .await
        .map(|_| multisig_op_pubkey)
}

pub async fn update_balance_account_name_hash(
    context: &mut BalanceAccountTestContext,
    account_name_hash: BalanceAccountNameHash,
    expected_error: Option<InstructionError>,
) -> Option<Pubkey> {
    let initiator_account =
        Keypair::from_base58_string(&context.initiator_account.to_base58_string());

    let init_result =
        init_balance_account_name_hash_update(context, &initiator_account, account_name_hash).await;

    let multisig_op_account = match expected_error {
        None => init_result.unwrap(),
        Some(error) => {
            assert_eq!(
                init_result.unwrap_err().unwrap(),
                TransactionError::InstructionError(1, error),
            );
            return None;
        }
    };

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account,
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    // finalize the config update
    let finalize_update_tx = Transaction::new_signed_with_payer(
        &[finalize_balance_account_name_update(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &multisig_op_account,
            &context.pt_context.payer.pubkey(),
            context.balance_account_guid_hash,
            account_name_hash,
        )],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );
    context
        .pt_context
        .banks_client
        .process_transaction(finalize_update_tx)
        .await
        .unwrap();

    Some(multisig_op_account)
}

pub async fn init_balance_account_policy_update(
    context: &mut BalanceAccountTestContext,
    initiator_account: &Keypair,
    update: BalanceAccountPolicyUpdate,
) -> Result<Pubkey, BanksClientError> {
    let rent = context.pt_context.banks_client.get_rent().await.unwrap();
    let multisig_op_rent = rent.minimum_balance(MultisigOp::LEN);
    let multisig_op_account = Keypair::new();
    let multisig_op_pubkey = multisig_op_account.pubkey();

    let init_update_tx = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.pt_context.payer.pubkey(),
                &multisig_op_pubkey,
                multisig_op_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            init_balance_account_policy_update_instruction(
                &context.program_id,
                &context.wallet_account.pubkey(),
                &multisig_op_pubkey,
                &initiator_account.pubkey(),
                context.balance_account_guid_hash,
                update.clone(),
            ),
        ],
        Some(&context.pt_context.payer.pubkey()),
        &[
            &context.pt_context.payer,
            &multisig_op_account,
            &initiator_account,
        ],
        context.pt_context.last_blockhash,
    );

    context
        .pt_context
        .banks_client
        .process_transaction(init_update_tx)
        .await
        .map(|_| multisig_op_pubkey)
}

pub async fn update_balance_account_policy(
    context: &mut BalanceAccountTestContext,
    update: BalanceAccountPolicyUpdate,
    expected_error: Option<InstructionError>,
) -> Option<Pubkey> {
    let initiator_account =
        Keypair::from_base58_string(&context.initiator_account.to_base58_string());

    let init_result =
        init_balance_account_policy_update(context, &initiator_account, update.clone()).await;

    let multisig_op_account = match expected_error {
        None => init_result.unwrap(),
        Some(error) => {
            assert_eq!(
                init_result.unwrap_err().unwrap(),
                TransactionError::InstructionError(1, error),
            );
            return None;
        }
    };

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account,
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    let finalize_update_tx = Transaction::new_signed_with_payer(
        &[finalize_balance_account_policy_update_instruction(
            &context.program_id,
            &context.wallet_account.pubkey(),
            &multisig_op_account,
            &context.pt_context.payer.pubkey(),
            context.balance_account_guid_hash,
            update.clone(),
        )],
        Some(&context.pt_context.payer.pubkey()),
        &[&context.pt_context.payer],
        context.pt_context.last_blockhash,
    );
    context
        .pt_context
        .banks_client
        .process_transaction(finalize_update_tx)
        .await
        .unwrap();

    Some(multisig_op_account)
}

pub struct SPLTestContext {
    pub mint: Keypair,
    pub mint_authority: Keypair,
    pub source_token_address: Pubkey,
    pub destination_token_address: Pubkey,
}

pub async fn setup_spl_transfer_test(
    context: &mut BalanceAccountTestContext,
    source_account: &Pubkey,
    fund_source_account_to_pay_for_destination_token_account: bool,
) -> SPLTestContext {
    let rent = context.pt_context.banks_client.get_rent().await.unwrap();
    let mint_account_rent = rent.minimum_balance(spl_token::state::Mint::LEN);
    let mint = Keypair::new();
    let mint_authority = Keypair::new();
    let source_token_address =
        spl_associated_token_account::get_associated_token_address(source_account, &mint.pubkey());
    let destination_token_address = spl_associated_token_account::get_associated_token_address(
        &context.destination.pubkey(),
        &mint.pubkey(),
    );

    context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[
                system_instruction::create_account(
                    &context.pt_context.payer.pubkey(),
                    &mint.pubkey(),
                    mint_account_rent,
                    spl_token::state::Mint::LEN as u64,
                    &spl_token::id(),
                ),
                system_instruction::create_account(
                    &context.pt_context.payer.pubkey(),
                    &mint_authority.pubkey(),
                    0,
                    0,
                    &system_program::id(),
                ),
                spl_token::instruction::initialize_mint(
                    &spl_token::id(),
                    &mint.pubkey(),
                    &mint_authority.pubkey(),
                    Some(&mint_authority.pubkey()),
                    6,
                )
                .unwrap(),
                spl_associated_token_account::create_associated_token_account(
                    &context.pt_context.payer.pubkey(),
                    source_account,
                    &mint.pubkey(),
                ),
                system_instruction::create_account(
                    &context.pt_context.payer.pubkey(),
                    &context.destination.pubkey(),
                    0,
                    0,
                    &system_program::id(),
                ),
                spl_token::instruction::mint_to(
                    &spl_token::id(),
                    &mint.pubkey(),
                    &source_token_address,
                    &mint_authority.pubkey(),
                    &[],
                    1000,
                )
                .unwrap(),
            ],
            Some(&context.pt_context.payer.pubkey()),
            &[
                &context.pt_context.payer,
                &mint,
                &mint_authority,
                &context.destination,
            ],
            context.pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    if fund_source_account_to_pay_for_destination_token_account {
        // transfer enough balance from fee payer to source account to pay for creating destination token account
        let token_account_rent = rent.minimum_balance(spl_token::state::Account::LEN);
        context
            .pt_context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[system_instruction::transfer(
                    &context.pt_context.payer.pubkey(),
                    source_account,
                    token_account_rent,
                )],
                Some(&context.pt_context.payer.pubkey()),
                &[&context.pt_context.payer],
                context.pt_context.last_blockhash,
            ))
            .await
            .unwrap();
    }

    SPLTestContext {
        mint,
        mint_authority,
        source_token_address,
        destination_token_address,
    }
}

pub async fn get_token_balance(context: &mut BalanceAccountTestContext, account: &Pubkey) -> u64 {
    spl_token::state::Account::unpack_from_slice(
        context
            .pt_context
            .banks_client
            .get_account(*account)
            .await
            .unwrap()
            .unwrap()
            .data
            .as_slice(),
    )
    .unwrap()
    .amount
}

pub async fn get_wallet(banks_client: &mut BanksClient, account: &Pubkey) -> Wallet {
    Wallet::unpack_from_slice(
        banks_client
            .get_account(*account)
            .await
            .unwrap()
            .unwrap()
            .data(),
    )
    .unwrap()
}

pub fn assert_multisig_op_timestamps(
    multisig_op: &MultisigOp,
    initialized_at: SystemTime,
    approval_timeout: Duration,
) {
    let initialized_at_timestamp =
        initialized_at.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

    assert!(multisig_op.started_at - initialized_at_timestamp <= 2);
    assert!(
        multisig_op.expires_at - initialized_at_timestamp - approval_timeout.as_secs() as i64 <= 2
    );
}

pub fn assert_initialized_multisig_op(
    multisig_op: &MultisigOp,
    initialized_at: SystemTime,
    expected_approval_timeout: Duration,
    expected_dispositions_required: u8,
    expected_dispositions: &Vec<ApprovalDispositionRecord>,
    expected_op_disposition: OperationDisposition,
    expected_params: &MultisigOpParams,
) {
    assert!(multisig_op.is_initialized);
    assert_multisig_op_timestamps(&multisig_op, initialized_at, expected_approval_timeout);
    assert_eq!(
        multisig_op.dispositions_required,
        expected_dispositions_required
    );
    assert_eq!(
        multisig_op.disposition_records.to_set(),
        expected_dispositions.to_set()
    );
    assert_eq!(multisig_op.operation_disposition, expected_op_disposition);
    assert_eq!(multisig_op.params_hash.unwrap(), expected_params.hash());
}

pub fn assert_multisig_op_dispositions(
    multisig_op: &MultisigOp,
    expected_dispositions_required: u8,
    expected_dispositions: &Vec<ApprovalDispositionRecord>,
    expected_op_disposition: OperationDisposition,
) {
    assert_eq!(
        multisig_op.dispositions_required,
        expected_dispositions_required
    );
    assert_eq!(
        multisig_op.disposition_records.to_set(),
        expected_dispositions.to_set()
    );
    assert_eq!(multisig_op.operation_disposition, expected_op_disposition);
}

pub async fn verify_multisig_op_init_fails(
    banks_client: &mut BanksClient,
    recent_blockhash: Hash,
    payer: &Keypair,
    assistant_account: &Keypair,
    multisig_op_account: &Keypair,
    init_instruction: Instruction,
    expected_error: InstructionError,
) {
    let transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &multisig_op_account.pubkey(),
                banks_client
                    .get_rent()
                    .await
                    .unwrap()
                    .minimum_balance(MultisigOp::LEN),
                MultisigOp::LEN as u64,
                &init_instruction.program_id,
            ),
            init_instruction,
        ],
        Some(&payer.pubkey()),
        &[&payer, multisig_op_account, &assistant_account],
        recent_blockhash,
    );

    assert_eq!(
        banks_client
            .process_transaction(transaction)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(1, expected_error),
    );
}

pub async fn process_wrap(
    context: &mut BalanceAccountTestContext,
    multisig_account_rent: u64,
    balance_account: Pubkey,
    amount: u64,
    token_account_rent: u64,
    wrapped_sol_account: Pubkey,
) -> Result<(), BanksClientError> {
    let multisig_op_account = Keypair::new();

    let init_result = context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[
                system_instruction::create_account(
                    &context.pt_context.payer.pubkey(),
                    &multisig_op_account.pubkey(),
                    multisig_account_rent,
                    MultisigOp::LEN as u64,
                    &context.program_id,
                ),
                instructions::init_wrap_unwrap(
                    &context.program_id,
                    &context.wallet_account.pubkey(),
                    &multisig_op_account.pubkey(),
                    &context.assistant_account.pubkey(),
                    &balance_account,
                    &context.balance_account_guid_hash,
                    amount,
                    WrapDirection::WRAP,
                ),
            ],
            Some(&context.pt_context.payer.pubkey()),
            &[
                &context.pt_context.payer,
                &multisig_op_account,
                &context.assistant_account,
            ],
            context.pt_context.last_blockhash,
        ))
        .await;

    if let Err(_) = init_result {
        return init_result;
    }

    assert_eq!(
        context
            .pt_context
            .banks_client
            .get_balance(wrapped_sol_account)
            .await
            .unwrap(),
        token_account_rent
    );

    assert_eq!(
        get_token_balance(context.borrow_mut(), &wrapped_sol_account).await,
        0
    );

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account.pubkey(),
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[instructions::finalize_wrap_unwrap(
                &context.program_id,
                &multisig_op_account.pubkey(),
                &context.wallet_account.pubkey(),
                &balance_account,
                &context.pt_context.payer.pubkey(),
                &context.balance_account_guid_hash,
                amount,
                WrapDirection::WRAP,
            )],
            Some(&context.pt_context.payer.pubkey()),
            &[&context.pt_context.payer],
            context.pt_context.last_blockhash,
        ))
        .await
}

pub async fn process_unwrapping(
    context: &mut BalanceAccountTestContext,
    multisig_account_rent: u64,
    balance_account: Pubkey,
    unwrap_amount: u64,
) -> Result<(), BanksClientError> {
    let unwrap_multisig_op_account = Keypair::new();

    context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[
                system_instruction::create_account(
                    &context.pt_context.payer.pubkey(),
                    &unwrap_multisig_op_account.pubkey(),
                    multisig_account_rent,
                    MultisigOp::LEN as u64,
                    &context.program_id,
                ),
                instructions::init_wrap_unwrap(
                    &context.program_id,
                    &context.wallet_account.pubkey(),
                    &unwrap_multisig_op_account.pubkey(),
                    &context.assistant_account.pubkey(),
                    &balance_account,
                    &context.balance_account_guid_hash,
                    unwrap_amount,
                    WrapDirection::UNWRAP,
                ),
            ],
            Some(&context.pt_context.payer.pubkey()),
            &[
                &context.pt_context.payer,
                &unwrap_multisig_op_account,
                &context.assistant_account,
            ],
            context.pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    approve_or_deny_n_of_n_multisig_op(
        context.pt_context.banks_client.borrow_mut(),
        &context.program_id,
        &unwrap_multisig_op_account.pubkey(),
        vec![&context.approvers[0], &context.approvers[1]],
        &context.pt_context.payer,
        context.pt_context.last_blockhash,
        ApprovalDisposition::APPROVE,
        OperationDisposition::APPROVED,
    )
    .await;

    context
        .pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &[instructions::finalize_wrap_unwrap(
                &context.program_id,
                &unwrap_multisig_op_account.pubkey(),
                &context.wallet_account.pubkey(),
                &balance_account,
                &context.pt_context.payer.pubkey(),
                &context.balance_account_guid_hash,
                unwrap_amount,
                WrapDirection::UNWRAP,
            )],
            Some(&context.pt_context.payer.pubkey()),
            &[&context.pt_context.payer],
            context.pt_context.last_blockhash,
        ))
        .await
}

pub async fn verify_address_book(
    context: &mut BalanceAccountTestContext,
    address_book_entries: Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    whitelist_entries: Vec<AddressBookEntry>,
) {
    let wallet = get_wallet(
        &mut context.pt_context.banks_client,
        &context.wallet_account.pubkey(),
    )
    .await;
    assert_eq!(
        wallet.address_book.filled_slots().len(),
        address_book_entries.len()
    );
    assert_eq!(wallet.address_book.filled_slots(), address_book_entries);
    let balance_account = wallet
        .get_balance_account(&context.balance_account_guid_hash)
        .unwrap();
    assert_eq!(
        whitelist_entries.to_set(),
        wallet.get_allowed_destinations(&balance_account).to_set()
    );
}

/// Generate a random BalanceAccountGuidHash
pub fn random_balance_account_guid_hash() -> BalanceAccountGuidHash {
    BalanceAccountGuidHash::new(&Pubkey::new_unique().to_bytes())
}

/// Hash vector of signer keys
pub fn hash_signers(signers: &Vec<Signer>) -> Hash {
    let mut bytes: Vec<u8> = Vec::new();
    for signer in signers {
        bytes.extend_from_slice(signer.key.as_ref());
    }
    hash(&bytes)
}

/// Hash vector of signer keys
pub fn hash_allowed_destination(
    destinations_to_add: &Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    destinations_to_remove: &Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
) -> Hash {
    let mut bytes: Vec<u8> = Vec::new();
    for (_, entry) in destinations_to_add {
        bytes.extend_from_slice(entry.name_hash.to_bytes());
    }
    bytes.push(1);
    for (_, entry) in destinations_to_remove {
        bytes.extend_from_slice(entry.name_hash.to_bytes());
    }
    hash(&bytes)
}

/// Hash vector of signer keys
pub fn hash_allowed_destinations(
    destinations: &Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
) -> Hash {
    let mut bytes: Vec<u8> = Vec::new();
    for (_, entry) in destinations {
        bytes.extend_from_slice(entry.name_hash.to_bytes());
    }
    hash(&bytes)
}

/// Derive BalanceAccount account PDAs from their GUID hashes.
pub fn find_balance_account_addresses(
    wallet_guid_hash: &WalletGuidHash,
    hashes: &Vec<BalanceAccountGuidHash>,
    program_id: &Pubkey,
) -> Vec<Pubkey> {
    hashes
        .iter()
        .map(|hash| BalanceAccount::find_address(wallet_guid_hash, hash, &program_id).0)
        .collect()
}

/// Derive associated token account addresses from corresponding BalanceAccount
/// addresses.
pub fn get_associated_token_account_addresses(
    balance_account_addresses: &Vec<Pubkey>,
    token_mint_address: &Pubkey,
) -> Vec<Pubkey> {
    balance_account_addresses
        .iter()
        .map(|balance_account_pda| {
            spl_associated_token_account::get_associated_token_address(
                &balance_account_pda,
                token_mint_address,
            )
        })
        .collect()
}
/// Create a wallet with a barebones config. no adressbook entries or dapps.
pub async fn create_wallet(
    context: &mut TestContext,
    wallet_keypair: &Keypair,
    wallet_guid_hash: &WalletGuidHash,
    assistant_keypair: &Keypair,
    signer_keypairs: &Vec<Keypair>,
) {
    init_wallet(
        &mut context.banks_client,
        &context.payer,
        context.recent_blockhash,
        &context.program_id,
        &wallet_keypair,
        &assistant_keypair,
        *wallet_guid_hash,
        InitialWalletConfig {
            approvals_required_for_config: 1,
            approval_timeout_for_config: Duration::from_secs(3600),
            signers: signer_keypairs
                .iter()
                .enumerate()
                .map(|(i, s)| (SlotId::new(i), s.pubkey_as_signer()))
                .collect(),
            config_approvers: signer_keypairs
                .iter()
                .enumerate()
                .map(|(i, _)| SlotId::new(i))
                .collect(),
        },
    )
    .await
    .unwrap();
}

/// Create multiple BalanceAccounts and optionally fund them, using
/// context.payer. Return a vec of tuples, containing the GUID Hash and a nested
/// PDA tuple, containing the PDA address and bump seed.
pub async fn create_balance_accounts(
    context: &mut TestContext,
    wallet_address: &Pubkey,
    wallet_guid_hash: &WalletGuidHash,
    assistant_keypair: &Keypair,
    approver_keypairs: &Vec<Keypair>,
    count: u8,
    lamports: Option<u64>,
) -> Vec<(BalanceAccountGuidHash, (Pubkey, u8))> {
    // accumulate created GUID hashes into vec and return
    let mut accounts: Vec<(BalanceAccountGuidHash, (Pubkey, u8))> =
        Vec::with_capacity(count as usize);

    for i in 0..count {
        let name = format!("Account {}", i + 1);
        let slot_id = SlotId::<BalanceAccount>::new(i.into());
        accounts.push(
            create_balance_account(
                context,
                slot_id,
                wallet_address,
                wallet_guid_hash,
                assistant_keypair,
                approver_keypairs,
                1,
                Duration::from_secs(1000),
                &name,
                lamports,
                i as u8, // address book slot index for this balance account
            )
            .await,
        );
    }
    accounts
}

/// Create a BalanceAccount and optionally fund it.
pub async fn create_balance_account(
    context: &mut TestContext,
    slot_id: SlotId<BalanceAccount>,
    wallet_address: &Pubkey,
    wallet_guid_hash: &WalletGuidHash,
    assistant_keypair: &Keypair,
    approver_keypairs: &Vec<Keypair>,
    approvals_required_for_transfer: u8,
    approval_timeout_for_transfer: Duration,
    name: &str,
    some_lamports: Option<u64>,
    address_book_slot_index: u8,
) -> (BalanceAccountGuidHash, (Pubkey, u8)) {
    let rent = context.banks_client.get_rent().await.unwrap();

    let multisig_op_account = Keypair::new();
    let multisig_account_rent = rent.minimum_balance(MultisigOp::LEN);
    let slot_for_balance_account_address = SlotId::new(address_book_slot_index as usize);
    let balance_account_name_hash = BalanceAccountNameHash::new(&hash_of(name.as_bytes()));
    let balance_account_guid_hash =
        BalanceAccountGuidHash::new(&hash_of(Uuid::new_v4().as_bytes()));

    let creation_params = BalanceAccountCreation {
        slot_id,
        name_hash: balance_account_name_hash,
        approvals_required_for_transfer,
        approval_timeout_for_transfer,
        transfer_approvers: approver_keypairs
            .iter()
            .enumerate()
            .map(|(i, _)| SlotId::new(i))
            .collect(),
        signers_hash: hash_signers(
            &approver_keypairs
                .iter()
                .map(|s| s.pubkey_as_signer())
                .collect(),
        ),
        whitelist_enabled: BooleanSetting::Off,
        dapps_enabled: BooleanSetting::Off,
        address_book_slot_id: slot_for_balance_account_address,
    };

    let init_transaction = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.payer.pubkey(),
                &multisig_op_account.pubkey(),
                multisig_account_rent,
                MultisigOp::LEN as u64,
                &context.program_id,
            ),
            init_balance_account_creation_instruction(
                &context.program_id,
                &wallet_address,
                &multisig_op_account.pubkey(),
                &assistant_keypair.pubkey(),
                slot_id,
                balance_account_guid_hash,
                balance_account_name_hash,
                approvals_required_for_transfer,
                approval_timeout_for_transfer,
                approver_keypairs
                    .iter()
                    .enumerate()
                    .map(|(i, _)| SlotId::new(i))
                    .collect(),
                hash_signers(
                    &approver_keypairs
                        .iter()
                        .map(|s| s.pubkey_as_signer())
                        .collect(),
                ),
                BooleanSetting::Off,
                BooleanSetting::Off,
                slot_for_balance_account_address,
            ),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer, &multisig_op_account, &assistant_keypair],
        context.recent_blockhash,
    );
    context
        .banks_client
        .process_transaction(init_transaction)
        .await
        .unwrap();

    approve_or_deny_1_of_2_multisig_op(
        context.banks_client.borrow_mut(),
        &context.program_id,
        &multisig_op_account.pubkey(),
        &approver_keypairs[0],
        &context.payer,
        &approver_keypairs[1].pubkey(),
        context.recent_blockhash,
        ApprovalDisposition::APPROVE,
    )
    .await;

    let finalize_transaction = Transaction::new_signed_with_payer(
        &[instructions::finalize_balance_account_creation(
            &context.program_id,
            &wallet_address,
            &multisig_op_account.pubkey(),
            &context.payer.pubkey(),
            balance_account_guid_hash,
            creation_params.clone(),
        )],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.recent_blockhash,
    );
    context
        .banks_client
        .process_transaction(finalize_transaction)
        .await
        .unwrap();

    // derive PDA of BalanceAccount from its GUID hash
    let (pda, bump) = BalanceAccount::find_address(
        wallet_guid_hash,
        &balance_account_guid_hash,
        &context.program_id,
    );

    // fund the account
    if let Some(lamports) = some_lamports {
        context
            .banks_client
            .process_transaction(Transaction::new_signed_with_payer(
                &[system_instruction::transfer(
                    &context.payer.pubkey(),
                    &pda,
                    lamports,
                )],
                Some(&context.payer.pubkey()),
                &[&context.payer],
                context.recent_blockhash,
            ))
            .await
            .unwrap();
    }

    (balance_account_guid_hash, (pda, bump))
}

pub async fn create_program_buffer(
    pt_context: &mut ProgramTestContext,
    buffer_account: &Keypair,
    data: Vec<u8>,
) {
    let rent = pt_context.banks_client.get_rent().await.unwrap();
    let buffer_rent = rent.minimum_balance(data.len() + 37);
    pt_context
        .banks_client
        .process_transaction(Transaction::new_signed_with_payer(
            &create_buffer(
                &pt_context.payer.pubkey(),
                &buffer_account.pubkey(),
                &pt_context.payer.pubkey(),
                buffer_rent,
                data.len(),
            )
            .unwrap(),
            Some(&pt_context.payer.pubkey()),
            &[&pt_context.payer, &buffer_account],
            pt_context.last_blockhash,
        ))
        .await
        .unwrap();

    let chunk_size = 1280 - 40 - 8 - 300;
    let transactions = data
        .chunks(chunk_size)
        .enumerate()
        .map(|(i, chunk)| {
            Transaction::new_signed_with_payer(
                &[write(
                    &buffer_account.pubkey(),
                    &pt_context.payer.pubkey(),
                    (i * chunk_size) as u32,
                    chunk.to_vec(),
                )],
                Some(&pt_context.payer.pubkey()),
                &[&pt_context.payer],
                pt_context.last_blockhash,
            )
        })
        .collect::<Vec<Transaction>>();

    for transaction in transactions {
        pt_context
            .banks_client
            .process_transaction(transaction.clone())
            .await
            .unwrap()
    }
}
