use std::convert::TryInto;

use solana_program::program_error::ProgramError;
use solana_program::pubkey::{Pubkey, PUBKEY_BYTES};

use crate::model::wallet_config::AllowedDestination;
use crate::model::multisig_op::ApprovalDisposition;

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
    /// 1. `[writable]` The wallet config account
    /// 2. `[signer]` The rent collector account
    FinalizeWalletCreation {
        wallet_guid_hash: [u8; 32],
        config_update: WalletConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[]` The wallet config account
    /// 2. `[]` The program config account
    /// 3. `[signer]` The initiator account (either the transaction assistant or an approver)
    InitWalletConfigUpdate {
        wallet_guid_hash: [u8; 32],
        config_update: WalletConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[writable]` The wallet config account
    /// 2. `[signer]` The rent collector account
    FinalizeWalletConfigUpdate {
        wallet_guid_hash: [u8; 32],
        config_update: WalletConfigUpdate
    },

    /// 0  `[writable]` The multisig operation account
    /// 1. `[]` The wallet config account
    /// 2. `[]` The source account
    /// 3. `[]` The destination account
    /// 4. `[signer]` The fee payer account
    /// 5. `[]` The program config account
    /// 6. `[signer]` The initiator account (either the transaction assistant or an approver)
    InitTransfer {
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
    /// 1. `[writable]` The source account
    /// 2. `[writable]` The destination account
    /// 3. `[]` The wallet config account
    /// 4. `[]` The system program
    /// 5. `[signer]` The rent collector account
    /// 6. `[writable]` The source token account, if this is an SPL transfer
    /// 7. `[writable]` The destination token account, if this is an SPL transfer
    /// 8. `[]` The SPL token program account, if this is an SPL transfer
    /// 9. `[]` The token mint authority, if this is an SPL transfer
    FinalizeTransfer {
        amount: u64,
        token_mint: Pubkey,
    }
}

impl ProgramInstruction {
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
        let amount = bytes.get(..8)
            .and_then(|slice| slice.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(ProgramError::InvalidInstructionData)?;

        let destination_name_hash = bytes.get(8..40)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(ProgramError::InvalidInstructionData)?;

        let token_mint = Pubkey::new_from_array(
            bytes.get(40..72)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(ProgramError::InvalidInstructionData)?);

        Ok(Self::InitTransfer { amount, destination_name_hash, token_mint })
    }

    fn unpack_set_approval_disposition_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        let (disposition, _) = bytes.split_first().ok_or(ProgramError::InvalidInstructionData)?;
        Ok(Self::SetApprovalDisposition { disposition: ApprovalDisposition::from_u8(*disposition) })
    }

    fn unpack_finalize_transfer_instruction(bytes: &[u8]) -> Result<ProgramInstruction, ProgramError> {
        Ok(Self::FinalizeTransfer {
            amount: bytes.get(..8)
                .and_then(|slice| slice.try_into().ok())
                .map(u64::from_le_bytes)
                .ok_or(ProgramError::InvalidInstructionData)?,
            token_mint: Pubkey::new_from_array(
        bytes.get(8..40)
                .and_then(|slice| slice.try_into().ok())
                .ok_or(ProgramError::InvalidInstructionData)?)
        })
    }
}


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProgramConfigUpdate {
    pub approvals_required_for_config: u8,
    pub add_approvers: Vec<Pubkey>,
    pub remove_approvers: Vec<Pubkey>
}

impl ProgramConfigUpdate {
    fn unpack(bytes: &[u8]) -> Result<ProgramConfigUpdate, ProgramError> {
        if bytes.len() < 2 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (approvals_config_bytes, rest) = bytes.split_at(1);

        let add_approvers = unpack_approvers(rest)?;
        let (_, remove_approvers_bytes) = rest.split_at(add_approvers.len() * PUBKEY_BYTES + 1);
        let remove_approvers = unpack_approvers(remove_approvers_bytes)?;

        Ok(ProgramConfigUpdate {
            approvals_required_for_config: approvals_config_bytes[0],
            add_approvers,
            remove_approvers
        })
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        let add_approvers_offset = 1;
        let remove_approvers_offset = add_approvers_offset + 1 + self.add_approvers.len() * PUBKEY_BYTES;
        let len = remove_approvers_offset + 1 + self.remove_approvers.len() * PUBKEY_BYTES;

        dst.resize(dst.len() + len, 0);
        dst[0] = self.approvals_required_for_config;

        dst[add_approvers_offset] = self.add_approvers.len() as u8;
        dst[add_approvers_offset + 1..remove_approvers_offset]
            .chunks_exact_mut(PUBKEY_BYTES)
            .enumerate()
            .for_each(|(i, chunk)| chunk.copy_from_slice(&self.add_approvers[i].to_bytes()));

        dst[remove_approvers_offset] = self.remove_approvers.len() as u8;
        dst[remove_approvers_offset + 1..len]
            .chunks_exact_mut(PUBKEY_BYTES)
            .enumerate()
            .for_each(|(i, chunk)| chunk.copy_from_slice(&self.remove_approvers[i].to_bytes()));
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WalletConfigUpdate {
    pub name_hash: [u8; 32],
    pub approvals_required_for_transfer: u8,
    pub add_approvers: Vec<Pubkey>,
    pub remove_approvers: Vec<Pubkey>,
    pub add_allowed_destinations: Vec<AllowedDestination>,
    pub remove_allowed_destinations: Vec<AllowedDestination>,
}

impl WalletConfigUpdate {
    fn unpack(bytes: &[u8]) -> Result<WalletConfigUpdate, ProgramError> {
        if bytes.len() < 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (name_hash_bytes, rest) = bytes.split_at(32);
        let (approvals_config_bytes, rest) = rest.split_at(1);

        let add_approvers = unpack_approvers(rest)?;
        let (_, remove_approvers_bytes) = rest.split_at(add_approvers.len() * PUBKEY_BYTES + 1);
        let remove_approvers = unpack_approvers(remove_approvers_bytes)?;

        let (_, allowed_destinations_bytes) = rest.split_at((add_approvers.len() + remove_approvers.len()) * PUBKEY_BYTES + 2);
        let add_allowed_destinations = Self::unpack_allowed_destinations(allowed_destinations_bytes)?;
        let (_, remove_allowed_destinations_bytes) = allowed_destinations_bytes.split_at(add_allowed_destinations.len() * AllowedDestination::LEN + 1);
        let remove_allowed_destinations = Self::unpack_allowed_destinations(remove_allowed_destinations_bytes)?;

        Ok(WalletConfigUpdate {
            name_hash: name_hash_bytes.try_into().ok().ok_or(ProgramError::InvalidInstructionData)?,
            approvals_required_for_transfer: approvals_config_bytes[0],
            add_approvers,
            remove_approvers,
            add_allowed_destinations,
            remove_allowed_destinations
        })
    }

    fn unpack_allowed_destinations(bytes: &[u8]) -> Result<Vec<AllowedDestination>, ProgramError> {
        let (count, rest) = bytes.split_first().ok_or(ProgramError::InvalidInstructionData)?;
        return rest
            .get(0..usize::from(*count) * AllowedDestination::LEN).unwrap()
            .chunks_exact(AllowedDestination::LEN)
            .map(|chunk| AllowedDestination::unpack_from_slice(chunk))
            .collect::<Result<Vec<AllowedDestination>, ProgramError>>()
    }

    pub fn pack(&self, dst: &mut Vec<u8>) {
        let approvals_required_for_transfer_offset = 32;
        let add_approvers_offset = approvals_required_for_transfer_offset + 1;
        let remove_approvers_offset = add_approvers_offset + 1 + self.add_approvers.len() * PUBKEY_BYTES;
        let add_allowed_destinations_offset = remove_approvers_offset + 1 + self.remove_approvers.len() * PUBKEY_BYTES;
        let remove_allowed_destinations_offset = add_allowed_destinations_offset + 1 + self.add_allowed_destinations.len() * AllowedDestination::LEN;
        let len = remove_allowed_destinations_offset + 1 + self.remove_allowed_destinations.len() * AllowedDestination::LEN;

        dst.resize(dst.len() + len, 0);
        dst[0..approvals_required_for_transfer_offset].copy_from_slice(&self.name_hash);
        dst[approvals_required_for_transfer_offset] = self.approvals_required_for_transfer;

        dst[add_approvers_offset] = self.add_approvers.len() as u8;
        dst[add_approvers_offset + 1..remove_approvers_offset]
            .chunks_exact_mut(PUBKEY_BYTES)
            .enumerate()
            .for_each(|(i, chunk)| chunk.copy_from_slice(&self.add_approvers[i].to_bytes()));

        dst[remove_approvers_offset] = self.remove_approvers.len() as u8;
        dst[remove_approvers_offset + 1..add_allowed_destinations_offset]
            .chunks_exact_mut(PUBKEY_BYTES)
            .enumerate()
            .for_each(|(i, chunk)| chunk.copy_from_slice(&self.remove_approvers[i].to_bytes()));

        dst[add_allowed_destinations_offset] = self.add_allowed_destinations.len() as u8;
        dst[add_allowed_destinations_offset + 1..remove_allowed_destinations_offset]
            .chunks_exact_mut(AllowedDestination::LEN)
            .enumerate()
            .for_each(|(i, chunk)| self.add_allowed_destinations[i].pack_into_slice(chunk));

        dst[remove_allowed_destinations_offset] = self.remove_allowed_destinations.len() as u8;
        dst[remove_allowed_destinations_offset + 1..len]
            .chunks_exact_mut(AllowedDestination::LEN)
            .enumerate()
            .for_each(|(i, chunk)| self.remove_allowed_destinations[i].pack_into_slice(chunk));
    }
}

fn unpack_approvers(bytes: &[u8]) -> Result<Vec<Pubkey>, ProgramError> {
    let (count, rest) = bytes.split_first().ok_or(ProgramError::InvalidInstructionData)?;
    let approvers = rest
        .get(0..usize::from(*count) * PUBKEY_BYTES).unwrap()
        .chunks_exact(PUBKEY_BYTES)
        .map(|chunk| Pubkey::new(chunk))
        .collect();
    return Ok(approvers)
}

fn unpack_wallet_guid_hash(bytes: &[u8]) -> Result<[u8; 32], ProgramError> {
    bytes.get(..32)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ProgramError::InvalidInstructionData)
}

