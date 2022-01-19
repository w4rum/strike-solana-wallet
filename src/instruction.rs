use std::borrow::Borrow;
use std::convert::TryInto;
use std::mem::size_of;
use std::slice::Iter;
use itertools::Itertools;

use solana_program::program_error::ProgramError;
use solana_program::{
    pubkey::Pubkey,
    instruction::AccountMeta,
};
use solana_program::instruction::Instruction;
use solana_program::program_pack::Pack;

use crate::model::wallet_config::AddressBookEntry;
use crate::model::multisig_op::ApprovalDisposition;
use crate::model::signer::Signer;

#[derive(Debug)]
pub enum ProgramInstruction {
    /// 0. `[writable]` The program config account
    /// 1. `[signer]` The transaction assistant account
    Init {
        config_update: ProgramConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[]` The program config account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    InitConfigUpdate {
        config_update: ProgramConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[writable]` The program config account
    /// 2. `[signer]` The rent collector account
    FinalizeConfigUpdate {
        config_update: ProgramConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[]` The program config account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    InitWalletCreation {
        wallet_guid_hash: [u8; 32],
        config_update: WalletConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[writable]` The program config account
    /// 2. `[signer]` The rent collector account
    FinalizeWalletCreation {
        wallet_guid_hash: [u8; 32],
        config_update: WalletConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[]` The program config account
    /// 2. `[signer]` The initiator account (either the transaction assistant or an approver)
    InitWalletConfigUpdate {
        wallet_guid_hash: [u8; 32],
        config_update: WalletConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[writable]` The program config account
    /// 2. `[signer]` The rent collector account
    FinalizeWalletConfigUpdate {
        wallet_guid_hash: [u8; 32],
        config_update: WalletConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[]` The program config account
    /// 2. `[]` The destination account
    /// 3. `[signer]` The fee payer account
    /// 4. `[signer]` The initiator account (either the transaction assistant or an approver)
    InitTransfer {
        wallet_guid_hash: [u8; 32],
        amount: u64,
        destination_name_hash: [u8; 32],
        token_mint: Pubkey,
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[signer]` The approver account
    /// 2. `[signer]` The fee payer account
    SetApprovalDisposition {
        disposition: ApprovalDisposition
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[]` The program config account
    /// 2. `[writable]` The source account
    /// 3. `[writable]` The destination account
    /// 4. `[]` The system program
    /// 5. `[signer]` The rent collector account
    /// 6. `[writable]` The source token account, if this is an SPL transfer
    /// 7. `[writable]` The destination token account, if this is an SPL transfer
    /// 8. `[]` The SPL token program account, if this is an SPL transfer
    /// 9. `[]` The token mint authority, if this is an SPL transfer
    FinalizeTransfer {
        wallet_guid_hash: [u8; 32],
        amount: u64,
        token_mint: Pubkey,
    }
}

impl ProgramInstruction {
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(size_of::<Self>());
        match self {
            &ProgramInstruction::Init {
                ref config_update
            } => {
                buf.push(0);
                config_update.pack(&mut buf);
            }
            _ => ()
        }
        buf
    }

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let (tag, rest) = input.split_first().ok_or(ProgramError::InvalidInstructionData)?;

        Ok(match tag {
            0 => Self::unpack_init_instruction(rest)?,
            1 => Self::unpack_init_config_update_instruction(rest)?,
            2 => Self::unpack_finalize_config_update_instruction(rest)?,
            3 => Self::unpack_init_wallet_creation_instruction(rest)?,
            4 => Self::unpack_finalize_wallet_creation_instruction(rest)?,
            5 => Self::unpack_init_wallet_policy_update_instruction(rest)?,
            6 => Self::unpack_finalize_wallet_policy_update_instruction(rest)?,
            7 => Self::unpack_init_transfer_for_approval_instruction(rest)?,
            8 => Self::unpack_finalize_transfer_instruction(rest)?,
            9 => Self::unpack_set_approval_disposition_instruction(rest)?,
            _ => return Err(ProgramError::InvalidInstructionData),
        })
    }

    fn unpack_init_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::Init {
            config_update: ProgramConfigUpdate::unpack(bytes)?
        })
    }

    fn unpack_init_config_update_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::InitConfigUpdate {
            config_update: ProgramConfigUpdate::unpack(bytes)?
        })
    }

    fn unpack_finalize_config_update_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeConfigUpdate {
            config_update: ProgramConfigUpdate::unpack(bytes)?
        })
    }

    fn unpack_init_wallet_creation_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::InitWalletCreation {
            wallet_guid_hash: unpack_wallet_guid_hash(bytes)?,
            config_update: WalletConfigUpdate::unpack(bytes.get(32..).ok_or(ProgramError::InvalidInstructionData)?)?
        })
    }

    fn unpack_finalize_wallet_creation_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeWalletCreation {
            wallet_guid_hash: unpack_wallet_guid_hash(bytes)?,
            config_update: WalletConfigUpdate::unpack(bytes.get(32..).ok_or(ProgramError::InvalidInstructionData)?)?
        })
    }

    fn unpack_init_wallet_policy_update_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::InitWalletConfigUpdate {
            wallet_guid_hash: unpack_wallet_guid_hash(bytes)?,
            config_update: WalletConfigUpdate::unpack(bytes.get(32..).ok_or(ProgramError::InvalidInstructionData)?)?
        })
    }

    fn unpack_finalize_wallet_policy_update_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeWalletConfigUpdate {
            wallet_guid_hash: unpack_wallet_guid_hash(bytes)?,
            config_update: WalletConfigUpdate::unpack(bytes.get(32..).ok_or(ProgramError::InvalidInstructionData)?)?
        })
    }

    fn unpack_init_transfer_for_approval_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        let wallet_guid_hash = unpack_wallet_guid_hash(bytes)?;

        let amount = bytes.get(32..40)
            .and_then(|slice| slice.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(ProgramError::InvalidInstructionData)?;

        let destination_name_hash = bytes.get(40..72)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(ProgramError::InvalidInstructionData)?;

        let token_mint = Pubkey::new_from_array(
            bytes.get(72..104)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(ProgramError::InvalidInstructionData)?);

        Ok(Self::InitTransfer { wallet_guid_hash, amount, destination_name_hash, token_mint })
    }

    fn unpack_set_approval_disposition_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        let (disposition, _) = bytes.split_first().ok_or(ProgramError::InvalidInstructionData)?;
        Ok(Self::SetApprovalDisposition { disposition: ApprovalDisposition::from_u8(*disposition) })
    }

    fn unpack_finalize_transfer_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeTransfer {
            wallet_guid_hash: unpack_wallet_guid_hash(bytes)?,
            amount: bytes.get(32..40)
                .and_then(|slice| slice.try_into().ok())
                .map(u64::from_le_bytes)
                .ok_or(ProgramError::InvalidInstructionData)?,
            token_mint: Pubkey::new_from_array(
                bytes.get(40..72)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or(ProgramError::InvalidInstructionData)?)
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProgramConfigUpdate {
    pub approvals_required_for_config: u8,
    pub add_signers: Vec<Signer>,
    pub remove_signers: Vec<Signer>,
    pub add_config_approvers: Vec<Signer>,
    pub remove_config_approvers: Vec<Signer>,
    pub add_address_book_entries: Vec<AddressBookEntry>,
    pub remove_address_book_entries: Vec<AddressBookEntry>,
}

impl ProgramConfigUpdate {
    fn unpack(bytes: &[u8]) -> Result<ProgramConfigUpdate, ProgramError> {
        if bytes.len() < 7 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut iter = bytes.iter();
        let approvals_required_for_config = *iter.next().ok_or(ProgramError::InvalidInstructionData)?;

        let add_signers = read_signers(&mut iter)?;
        let remove_signers = read_signers(&mut iter)?;
        let add_config_approvers = read_signers(&mut iter)?;
        let remove_config_approvers = read_signers(&mut iter)?;
        let add_address_book_entries = read_address_book_entries(&mut iter)?;
        let remove_address_book_entries = read_address_book_entries(&mut iter)?;

        Ok(ProgramConfigUpdate {
            approvals_required_for_config,
            add_signers,
            remove_signers,
            add_config_approvers,
            remove_config_approvers,
            add_address_book_entries,
            remove_address_book_entries
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        dst.push(self.approvals_required_for_config);
        append_signers(&self.add_signers, dst);
        append_signers(&self.remove_signers, dst);
        append_signers(&self.add_config_approvers, dst);
        append_signers(&self.remove_config_approvers, dst);
        append_address_book_entries(&self.add_address_book_entries, dst);
        append_address_book_entries(&self.remove_address_book_entries, dst);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WalletConfigUpdate {
    pub name_hash: [u8; 32],
    pub approvals_required_for_transfer: u8,
    pub add_transfer_approvers: Vec<Signer>,
    pub remove_transfer_approvers: Vec<Signer>,
    pub add_allowed_destinations: Vec<AddressBookEntry>,
    pub remove_allowed_destinations: Vec<AddressBookEntry>,
}

impl WalletConfigUpdate {
    fn unpack(bytes: &[u8]) -> Result<WalletConfigUpdate, ProgramError> {
        if bytes.len() < 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut iter = bytes.iter();
        let name_hash: [u8; 32] = *read_fixed_size_array(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;
        let approvals_required_for_transfer = *read_u8(&mut iter).ok_or(ProgramError::InvalidInstructionData)?;

        let add_approvers = read_signers(&mut iter)?;
        let remove_approvers = read_signers(&mut iter)?;
        let add_allowed_destinations = read_address_book_entries(&mut iter)?;
        let remove_allowed_destinations = read_address_book_entries(&mut iter)?;

        Ok(WalletConfigUpdate {
            name_hash,
            approvals_required_for_transfer,
            add_transfer_approvers: add_approvers,
            remove_transfer_approvers: remove_approvers,
            add_allowed_destinations,
            remove_allowed_destinations
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.name_hash);
        dst.push(self.approvals_required_for_transfer);
        append_signers(&self.add_transfer_approvers, dst);
        append_signers(&self.remove_transfer_approvers, dst);
        append_address_book_entries(&self.add_allowed_destinations, dst);
        append_address_book_entries(&self.remove_allowed_destinations, dst);
    }
}

fn read_signers(iter: &mut Iter<u8>) -> Result<Vec<Signer>, ProgramError> {
    let signers_count = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
    read_slice(iter, usize::from(signers_count) * Signer::LEN)
        .ok_or(ProgramError::InvalidInstructionData)?
        .chunks_exact(Signer::LEN)
        .map(|chunk| Signer::unpack_from_slice(chunk))
        .collect()
}

fn read_u8<'a>(iter: &'a mut Iter<u8>) -> Option<&'a u8> {
    iter.next()
}

fn read_fixed_size_array<'a, const SIZE: usize>(iter: &'a mut Iter<u8>) -> Option<&'a [u8; SIZE]> {
    read_slice(iter, SIZE).and_then(|slice| slice.try_into().ok())
}

fn read_slice<'a>(iter: &'a mut Iter<u8>, size: usize) -> Option<&'a [u8]> {
    let slice = iter.as_slice().get(0..size);
    if slice.is_some() {
        for _ in 0..size {
            iter.next();
        }
    }
    return slice;
}

fn append_signers(signers: &Vec<Signer>, dst: &mut Vec<u8>) {
    dst.push(signers.len() as u8);
    for signer in signers.iter() {
        let mut buf = vec![0; Signer::LEN];
        signer.pack_into_slice(&mut buf);
        dst.extend_from_slice(buf.as_slice());
    }
}

fn read_address_book_entries(iter: &mut Iter<u8>) -> Result<Vec<AddressBookEntry>, ProgramError> {
    let entries_count = *read_u8(iter).ok_or(ProgramError::InvalidInstructionData)?;
    read_slice(iter, usize::from(entries_count) * AddressBookEntry::LEN)
        .ok_or(ProgramError::InvalidInstructionData)?
        .chunks_exact(AddressBookEntry::LEN)
        .map(|chunk| AddressBookEntry::unpack_from_slice(chunk))
        .collect()
}

fn append_address_book_entries(entries: &Vec<AddressBookEntry>, dst: &mut Vec<u8>) {
    dst.push(entries.len() as u8);
    for entry in entries.iter() {
        let mut buf = vec![0; AddressBookEntry::LEN];
        entry.pack_into_slice(&mut buf);
        dst.extend_from_slice(buf.as_slice());
    }
}

fn unpack_wallet_guid_hash(bytes: &[u8]) -> Result<[u8; 32], ProgramError> {
    bytes.get(..32)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ProgramError::InvalidInstructionData)
}

pub fn program_init(
    program_id: &Pubkey,
    program_config_account: &Pubkey,
    assistant_account: &Pubkey,
    config_approvers: Vec<Pubkey>,
    approvals_required_for_config: u8,
    address_book: Vec<AddressBookEntry>
) -> Result<Instruction, ProgramError> {
    let data = ProgramInstruction::Init {
        config_update: ProgramConfigUpdate {
            approvals_required_for_config,
            add_signers: Vec::new(),
            remove_signers: Vec::new(),
            add_config_approvers: config_approvers.iter().map(|it| Signer { key: *it }).collect_vec(),
            remove_config_approvers: Vec::new(),
            add_address_book_entries: address_book,
            remove_address_book_entries: Vec::new()
        }
    }.borrow().pack();

    let accounts = vec![
        AccountMeta::new(*program_config_account, false),
        AccountMeta::new_readonly(*assistant_account, true),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data
    })
}
