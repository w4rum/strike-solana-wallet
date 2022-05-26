use solana_program::hash::Hash;

use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::pubkey::Pubkey;
use solana_program::{system_program, sysvar};
use std::borrow::Borrow;
use std::time::Duration;
use strike_wallet::instruction::ProgramInstruction::{Cleanup, Migrate};
use strike_wallet::instruction::{
    pack_supply_dapp_transaction_instructions, BalanceAccountAddressWhitelistUpdate,
    BalanceAccountCreation, BalanceAccountPolicyUpdate,
};
use strike_wallet::model::balance_account::BalanceAccount;
use strike_wallet::model::wallet::WalletGuidHash;
use strike_wallet::{
    instruction::{
        AddressBookUpdate, BalanceAccountWhitelistUpdate, DAppBookUpdate, InitialWalletConfig,
        ProgramInstruction, WalletConfigPolicyUpdate,
    },
    model::{
        address_book::{AddressBookEntry, AddressBookEntryNameHash, DAppBookEntry},
        balance_account::{BalanceAccountGuidHash, BalanceAccountNameHash},
        multisig_op::{ApprovalDisposition, BooleanSetting, SlotUpdateType, WrapDirection},
        signer::Signer,
    },
    utils,
    utils::SlotId,
};

pub fn init_wallet(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    assistant_account: &Pubkey,
    rent_return_account: &Pubkey,
    wallet_guid_hash: WalletGuidHash,
    initial_config: InitialWalletConfig,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new_readonly(*assistant_account, true),
        AccountMeta::new_readonly(*rent_return_account, true),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data: ProgramInstruction::InitWallet {
            wallet_guid_hash,
            initial_config,
        }
        .borrow()
        .pack(),
    }
}

fn init_multisig_op(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    program_instruction: ProgramInstruction,
) -> Instruction {
    let mut accounts = vec![AccountMeta::new(*multisig_op_account, false)];
    accounts.push(AccountMeta::new_readonly(*wallet_account, false));
    accounts.push(AccountMeta::new_readonly(*initiator_account, true));
    accounts.push(AccountMeta::new_readonly(sysvar::clock::id(), false));
    accounts.push(AccountMeta::new_readonly(*rent_return_account, true));

    Instruction {
        program_id: *program_id,
        accounts,
        data: program_instruction.borrow().pack(),
    }
}

pub fn set_approval_disposition(
    program_id: &Pubkey,
    multisig_op_account: &Pubkey,
    approver: &Pubkey,
    disposition: ApprovalDisposition,
    params_hash: Hash,
) -> Instruction {
    let data = ProgramInstruction::SetApprovalDisposition {
        disposition,
        params_hash,
    }
    .borrow()
    .pack();

    let accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new_readonly(*approver, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

const FEE_AMOUNT: u64 = 0;
const FEE_ACCOUNT_GUID_HASH_NONE: Option<BalanceAccountGuidHash> = None;

pub fn init_balance_account_creation_instruction(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    slot_id: SlotId<BalanceAccount>,
    account_guid_hash: BalanceAccountGuidHash,
    name_hash: BalanceAccountNameHash,
    approvals_required_for_transfer: u8,
    approval_timeout_for_transfer: Duration,
    approvers: Vec<SlotId<Signer>>,
    signers_hash: Hash,
    whitelist_enabled: BooleanSetting,
    dapps_enabled: BooleanSetting,
    address_book_slot_id: SlotId<AddressBookEntry>,
) -> Instruction {
    init_multisig_op(
        program_id,
        wallet_account,
        multisig_op_account,
        initiator_account,
        rent_return_account,
        ProgramInstruction::InitBalanceAccountCreation {
            fee_amount: FEE_AMOUNT,
            fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
            account_guid_hash,
            creation_params: BalanceAccountCreation {
                slot_id,
                name_hash,
                approvals_required_for_transfer,
                approval_timeout_for_transfer,
                transfer_approvers: approvers.clone(),
                signers_hash,
                whitelist_enabled,
                dapps_enabled,
                address_book_slot_id,
            },
        },
    )
}

pub fn finalize_balance_account_creation(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    creation_params: BalanceAccountCreation,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeBalanceAccountCreation {
        account_guid_hash,
        creation_params,
    }
    .borrow()
    .pack();
    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_dapp_book_update(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    update: DAppBookUpdate,
) -> Instruction {
    init_multisig_op(
        program_id,
        wallet_account,
        multisig_op_account,
        initiator_account,
        rent_return_account,
        ProgramInstruction::InitDAppBookUpdate {
            fee_amount: FEE_AMOUNT,
            fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
            update,
        },
    )
}

pub fn finalize_dapp_book_update(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    update: DAppBookUpdate,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeDAppBookUpdate { update }
        .borrow()
        .pack();
    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_balance_account_policy_update_instruction(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    update: BalanceAccountPolicyUpdate,
) -> Instruction {
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*multisig_op_account, false),
            AccountMeta::new(*wallet_account, false),
            AccountMeta::new_readonly(*initiator_account, true),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(*rent_return_account, true),
        ],
        data: ProgramInstruction::InitBalanceAccountPolicyUpdate {
            fee_amount: FEE_AMOUNT,
            fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
            account_guid_hash,
            update: update.clone(),
        }
        .borrow()
        .pack(),
    }
}

pub fn finalize_balance_account_policy_update_instruction(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    update: BalanceAccountPolicyUpdate,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data: ProgramInstruction::FinalizeBalanceAccountPolicyUpdate {
            account_guid_hash,
            update,
        }
        .borrow()
        .pack(),
    }
}

pub fn init_transfer(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    source_account: &Pubkey,
    destination_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    amount: u64,
    destination_name_hash: AddressBookEntryNameHash,
    token_mint: &Pubkey,
    fee_payer: &Pubkey,
) -> Instruction {
    let data = ProgramInstruction::InitTransfer {
        fee_amount: FEE_AMOUNT,
        fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
        account_guid_hash,
        amount,
        destination_name_hash,
    }
    .borrow()
    .pack();

    let destination_token_account =
        spl_associated_token_account::get_associated_token_address(destination_account, token_mint);

    let accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new_readonly(*wallet_account, false),
        AccountMeta::new(*source_account, false),
        AccountMeta::new_readonly(*destination_account, false),
        AccountMeta::new_readonly(*initiator_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new(*fee_payer, true),
        AccountMeta::new_readonly(*token_mint, false),
        AccountMeta::new(destination_token_account, false),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
        AccountMeta::new_readonly(spl_associated_token_account::id(), false),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn finalize_transfer(
    program_id: &Pubkey,
    multisig_op_account: &Pubkey,
    wallet_account: &Pubkey,
    source_account: &Pubkey,
    destination_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    amount: u64,
    token_mint: &Pubkey,
    token_authority: Option<&Pubkey>,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeTransfer {
        account_guid_hash,
        amount,
        token_mint: *token_mint,
    }
    .borrow()
    .pack();
    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new_readonly(*wallet_account, false),
        AccountMeta::new(*source_account, false),
        AccountMeta::new(*destination_account, false),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];
    if *token_mint != system_program::id() {
        // SPL
        accounts.extend_from_slice(&[
            AccountMeta::new(
                spl_associated_token_account::get_associated_token_address(
                    source_account,
                    &token_mint,
                ),
                false,
            ),
            AccountMeta::new(
                spl_associated_token_account::get_associated_token_address(
                    destination_account,
                    &token_mint,
                ),
                false,
            ),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(*token_authority.unwrap(), false),
        ])
    }

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_wrap_unwrap(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    balance_account: &Pubkey,
    account_guid_hash: &BalanceAccountGuidHash,
    amount: u64,
    direction: WrapDirection,
) -> Instruction {
    let data = ProgramInstruction::InitWrapUnwrap {
        fee_amount: FEE_AMOUNT,
        fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
        account_guid_hash: *account_guid_hash,
        amount,
        direction,
    }
    .borrow()
    .pack();

    let wrapped_sol_account = spl_associated_token_account::get_associated_token_address(
        balance_account,
        &spl_token::native_mint::id(),
    );

    let accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new_readonly(*wallet_account, false),
        AccountMeta::new(*balance_account, false),
        AccountMeta::new(wrapped_sol_account, false),
        AccountMeta::new_readonly(spl_token::native_mint::id(), false),
        AccountMeta::new_readonly(*initiator_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*rent_return_account, true),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
        AccountMeta::new_readonly(spl_associated_token_account::id(), false),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn finalize_wrap_unwrap(
    program_id: &Pubkey,
    multisig_op_account: &Pubkey,
    wallet_account: &Pubkey,
    balance_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: &BalanceAccountGuidHash,
    amount: u64,
    direction: WrapDirection,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeWrapUnwrap {
        account_guid_hash: *account_guid_hash,
        amount,
        direction,
    }
    .borrow()
    .pack();

    let wrapped_sol_account = spl_associated_token_account::get_associated_token_address(
        balance_account,
        &spl_token::native_mint::id(),
    );

    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new_readonly(*wallet_account, false),
        AccountMeta::new(*balance_account, false),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new(wrapped_sol_account, false),
        AccountMeta::new_readonly(spl_token::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_update_signer(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    slot_update_type: SlotUpdateType,
    slot_id: SlotId<Signer>,
    signer: Signer,
    fee_amount: Option<u64>,
    fee_account_guid_hash: Option<BalanceAccountGuidHash>,
) -> Instruction {
    init_multisig_op(
        program_id,
        wallet_account,
        multisig_op_account,
        initiator_account,
        rent_return_account,
        ProgramInstruction::InitUpdateSigner {
            fee_amount: fee_amount.unwrap_or(FEE_AMOUNT),
            fee_account_guid_hash,
            slot_update_type,
            slot_id,
            signer,
        },
    )
}

pub fn finalize_update_signer(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    slot_update_type: SlotUpdateType,
    slot_id: SlotId<Signer>,
    signer: Signer,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeUpdateSigner {
        slot_update_type,
        slot_id,
        signer,
    }
    .borrow()
    .pack();

    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_wallet_config_policy_update_instruction(
    program_id: Pubkey,
    wallet_account: Pubkey,
    multisig_op_account: Pubkey,
    initiator_account: Pubkey,
    rent_return_account: Pubkey,
    update: &WalletConfigPolicyUpdate,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(multisig_op_account, false),
            AccountMeta::new(wallet_account, false),
            AccountMeta::new_readonly(initiator_account, true),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(rent_return_account, true),
        ],
        data: ProgramInstruction::InitWalletConfigPolicyUpdate {
            fee_amount: FEE_AMOUNT,
            fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
            update: update.clone(),
        }
        .borrow()
        .pack(),
    }
}

pub fn finalize_wallet_config_policy_update_instruction(
    program_id: Pubkey,
    wallet_account: Pubkey,
    multisig_op_account: Pubkey,
    rent_return_account: Pubkey,
    update: &WalletConfigPolicyUpdate,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(multisig_op_account, false),
        AccountMeta::new(wallet_account, false),
        AccountMeta::new(rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id,
        accounts,
        data: ProgramInstruction::FinalizeWalletConfigPolicyUpdate {
            update: update.clone(),
        }
        .borrow()
        .pack(),
    }
}

pub fn init_dapp_transaction(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    multisig_data_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: &BalanceAccountGuidHash,
    dapp: DAppBookEntry,
    instruction_count: u8,
) -> Instruction {
    let data = ProgramInstruction::InitDAppTransaction {
        fee_amount: FEE_AMOUNT,
        fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
        account_guid_hash: *account_guid_hash,
        dapp,
        instruction_count,
    }
    .borrow()
    .pack();

    let accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*multisig_data_account, false),
        AccountMeta::new_readonly(*wallet_account, false),
        AccountMeta::new_readonly(*initiator_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*rent_return_account, true),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn supply_dapp_transaction_instructions(
    program_id: &Pubkey,
    multisig_op_account: &Pubkey,
    multisig_data_account: &Pubkey,
    initiator_account: &Pubkey,
    starting_index: u8,
    instructions: &Vec<Instruction>,
) -> Instruction {
    let mut data = Vec::<u8>::new();
    pack_supply_dapp_transaction_instructions(starting_index, instructions, &mut data);
    let accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*multisig_data_account, false),
        AccountMeta::new_readonly(*initiator_account, true),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn finalize_dapp_transaction(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    multisig_data_account: &Pubkey,
    balance_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: &BalanceAccountGuidHash,
    params_hash: &Hash,
    instructions: &Vec<Instruction>,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeDAppTransaction {
        account_guid_hash: *account_guid_hash,
        params_hash: *params_hash,
    }
    .borrow()
    .pack();

    // the accounts below are expected below in this order by finalize
    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*multisig_data_account, false),
        AccountMeta::new_readonly(*wallet_account, false),
        AccountMeta::new(*balance_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    // we also need to include any accounts referenced by the dapp instructions, but we don't
    // want to repeat keys
    let mut keys_to_skip = vec![
        *multisig_op_account,
        *multisig_data_account,
        *wallet_account,
        *balance_account,
        *rent_return_account,
        sysvar::clock::id(),
    ];

    // add the optional fee account if it is supplied
    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
        keys_to_skip.push(*fee_account);
        keys_to_skip.push(system_program::id());
    }

    accounts.extend(utils::unique_account_metas(&instructions, &keys_to_skip));

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_account_settings_update(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    whitelist_status: Option<BooleanSetting>,
    dapps_enabled: Option<BooleanSetting>,
    fee_amount: Option<u64>,
    fee_account_guid_hash: Option<BalanceAccountGuidHash>,
) -> Instruction {
    init_multisig_op(
        program_id,
        wallet_account,
        multisig_op_account,
        initiator_account,
        rent_return_account,
        ProgramInstruction::InitAccountSettingsUpdate {
            fee_amount: fee_amount.unwrap_or(FEE_AMOUNT),
            fee_account_guid_hash: if fee_account_guid_hash.is_some() {
                fee_account_guid_hash
            } else {
                FEE_ACCOUNT_GUID_HASH_NONE
            },
            account_guid_hash,
            whitelist_enabled: whitelist_status,
            dapps_enabled,
        },
    )
}

pub fn finalize_account_settings_update(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    whitelist_status: Option<BooleanSetting>,
    dapps_enabled: Option<BooleanSetting>,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeAccountSettingsUpdate {
        account_guid_hash,
        whitelist_enabled: whitelist_status,
        dapps_enabled,
    }
    .borrow()
    .pack();

    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_balance_account_name_update(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    account_name_hash: BalanceAccountNameHash,
) -> Instruction {
    init_multisig_op(
        program_id,
        wallet_account,
        multisig_op_account,
        initiator_account,
        rent_return_account,
        ProgramInstruction::InitBalanceAccountNameUpdate {
            fee_amount: FEE_AMOUNT,
            fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
            account_guid_hash,
            account_name_hash,
        },
    )
}

pub fn finalize_balance_account_name_update(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    account_name_hash: BalanceAccountNameHash,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeBalanceAccountNameUpdate {
        account_guid_hash,
        account_name_hash,
    }
    .borrow()
    .pack();

    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_address_book_update_instruction(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    add_address_book_entries: Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    remove_address_book_entries: Vec<(SlotId<AddressBookEntry>, AddressBookEntry)>,
    balance_account_whitelist_updates: Vec<BalanceAccountWhitelistUpdate>,
) -> Instruction {
    init_multisig_op(
        program_id,
        wallet_account,
        multisig_op_account,
        initiator_account,
        rent_return_account,
        ProgramInstruction::InitAddressBookUpdate {
            fee_amount: FEE_AMOUNT,
            fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
            update: AddressBookUpdate {
                add_address_book_entries: add_address_book_entries.clone(),
                remove_address_book_entries: remove_address_book_entries.clone(),
                balance_account_whitelist_updates: balance_account_whitelist_updates.clone(),
            },
        },
    )
}

pub fn finalize_address_book_update(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    update: AddressBookUpdate,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeAddressBookUpdate { update }
        .borrow()
        .pack();
    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_balance_account_enable_spl_token(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    token_mint_account: &Pubkey,
    associated_token_accounts: &Vec<Pubkey>,
    payer_account_guid_hash: &BalanceAccountGuidHash,
    account_guid_hashes: &Vec<BalanceAccountGuidHash>,
) -> Instruction {
    let data = ProgramInstruction::InitSPLTokenAccountsCreation {
        fee_amount: FEE_AMOUNT,
        fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
        payer_account_guid_hash: payer_account_guid_hash.clone(),
        account_guid_hashes: account_guid_hashes.clone(),
    }
    .borrow()
    .pack();

    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*initiator_account, true),
        AccountMeta::new(*token_mint_account, false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*rent_return_account, true),
    ];

    // append variable number of associated token accounts to array
    accounts.append(
        &mut associated_token_accounts
            .iter()
            .map(|pubkey| AccountMeta::new(*pubkey, false))
            .collect(),
    );

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn finalize_balance_account_enable_spl_token(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    token_mint_account: &Pubkey,
    payer_balance_account: &Pubkey,
    balance_accounts: &Vec<Pubkey>,
    associated_token_accounts: &Vec<Pubkey>,
    payer_account_guid_hash: &BalanceAccountGuidHash,
    account_guid_hashes: &Vec<BalanceAccountGuidHash>,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let data = ProgramInstruction::FinalizeSPLTokenAccountsCreation {
        payer_account_guid_hash: payer_account_guid_hash.clone(),
        account_guid_hashes: account_guid_hashes.clone(),
    }
    .borrow()
    .pack();

    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new(*token_mint_account, false),
        AccountMeta::new(*payer_balance_account, false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new_readonly(spl_associated_token_account::id(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];

    // concat accounts vec with Associated Token AccountMetas.
    accounts.append(
        &mut associated_token_accounts
            .iter()
            .map(|pubkey| AccountMeta::new(*pubkey, false))
            .collect(),
    );

    accounts.append(
        &mut balance_accounts
            .iter()
            .map(|pubkey| AccountMeta::new(*pubkey, false))
            .collect(),
    );

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn migrate_account(
    program_id: &Pubkey,
    source_account: &Pubkey,
    destination_account: &Pubkey,
    rent_return_account: &Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*source_account, false),
        AccountMeta::new(*destination_account, false),
        AccountMeta::new_readonly(*rent_return_account, true),
    ];

    let data = Migrate {}.borrow().pack();

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn cleanup_account(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    cleanup_account: &Pubkey,
    rent_return_account: &Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new_readonly(*wallet_account, false),
        AccountMeta::new(*cleanup_account, false),
        AccountMeta::new(*rent_return_account, false),
    ];

    let data = Cleanup {}.borrow().pack();

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

pub fn init_balance_account_address_whitelist_update_instruction(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    initiator_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    update: BalanceAccountAddressWhitelistUpdate,
) -> Instruction {
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*multisig_op_account, false),
            AccountMeta::new(*wallet_account, false),
            AccountMeta::new_readonly(*initiator_account, true),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(*rent_return_account, true),
        ],
        data: ProgramInstruction::InitBalanceAccountAddressWhitelistUpdate {
            fee_amount: FEE_AMOUNT,
            fee_account_guid_hash: FEE_ACCOUNT_GUID_HASH_NONE,
            account_guid_hash,
            update: update.clone(),
        }
        .borrow()
        .pack(),
    }
}

pub fn finalize_balance_account_address_whitelist_update_instruction(
    program_id: &Pubkey,
    wallet_account: &Pubkey,
    multisig_op_account: &Pubkey,
    rent_return_account: &Pubkey,
    account_guid_hash: BalanceAccountGuidHash,
    update: BalanceAccountAddressWhitelistUpdate,
    fee_account_maybe: Option<&Pubkey>,
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(*multisig_op_account, false),
        AccountMeta::new(*wallet_account, false),
        AccountMeta::new(*rent_return_account, true),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
    ];

    if let Some(fee_account) = fee_account_maybe {
        accounts.push(AccountMeta::new(*fee_account, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Instruction {
        program_id: *program_id,
        accounts,
        data: ProgramInstruction::FinalizeBalanceAccountAddressWhitelistUpdate {
            account_guid_hash,
            update,
        }
        .borrow()
        .pack(),
    }
}
