use crate::error::WalletError;
use crate::instruction::{append_instruction, read_instruction_from_slice};
use crate::model::address_book::DAppBookEntry;
use crate::model::balance_account::BalanceAccountGuidHash;
use crate::model::multisig_op::{common_data, MultisigOp};
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use bitvec::macros::internal::funty::Fundamental;
use bytes::BufMut;
use itertools::all;
use solana_program::entrypoint::ProgramResult;
use solana_program::hash::{hash, Hash};
use solana_program::instruction::Instruction;
use solana_program::msg;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{IsInitialized, Pack, Sealed};
use solana_program::pubkey::{Pubkey, PUBKEY_BYTES};

const INSTRUCTION_DATA_LEN: usize = 2500;
const MAX_INSTRUCTION_COUNT: usize = 32;

#[derive(Debug)]
pub struct DAppMultisigData {
    pub is_initialized: bool,
    pub wallet_address: Pubkey,
    pub account_guid_hash: BalanceAccountGuidHash,
    pub dapp: DAppBookEntry,
    pub num_instructions: u8,
    instruction_offsets: [u16; MAX_INSTRUCTION_COUNT],
    instruction_data: Vec<u8>,
    position: usize,
}

impl DAppMultisigData {
    pub fn init(
        &mut self,
        wallet_address: Pubkey,
        account_guid_hash: BalanceAccountGuidHash,
        dapp: DAppBookEntry,
        num_instructions: u8,
    ) -> ProgramResult {
        self.is_initialized = true;
        self.wallet_address = wallet_address;
        self.account_guid_hash = account_guid_hash;
        self.dapp = dapp;
        if num_instructions > MAX_INSTRUCTION_COUNT as u8 {
            return Err(WalletError::DAppInstructionOverflow.into());
        }
        self.num_instructions = num_instructions;
        self.instruction_offsets = [0; MAX_INSTRUCTION_COUNT];
        self.instruction_data = vec![0; INSTRUCTION_DATA_LEN];
        self.position = 0;

        Ok(())
    }

    pub fn add_instruction(&mut self, index: u8, instruction: &Instruction) -> ProgramResult {
        if self.is_initialized {
            if index >= self.num_instructions {
                msg!("Index {:} too large (>= {:})", index, self.num_instructions);
                return Err(WalletError::DAppInstructionOverflow.into());
            }
            if self.instruction_offsets[usize::from(index)] != 0 {
                return Err(WalletError::DAppInstructionAlreadySupplied.into());
            }
            let mut buffer = Vec::<u8>::new();
            append_instruction(instruction, &mut buffer);
            // the offset is 1-based, so that an offset of 0 can mean "unset"
            self.instruction_offsets[usize::from(index)] = (1 + self.position).as_u16();
            let new_position = self.position + buffer.len();
            if new_position >= INSTRUCTION_DATA_LEN {
                msg!("Instruction data exceeded buffer size");
                return Err(WalletError::DAppInstructionOverflow.into());
            }
            self.instruction_data[self.position..new_position].copy_from_slice(&buffer);
            self.position = new_position;
        }
        Ok(())
    }

    pub fn all_instructions_supplied(&self) -> bool {
        all(0..self.num_instructions, |x| {
            self.instruction_offsets[usize::from(x)] != 0
        })
    }

    pub fn hash(&self, multisig_op: &MultisigOp) -> Result<Hash, ProgramError> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(7);
        bytes.extend_from_slice(common_data(multisig_op).as_slice());
        bytes.extend_from_slice(&self.wallet_address.to_bytes());
        bytes.extend_from_slice(&self.account_guid_hash.to_bytes());
        let mut buf = vec![0; DAppBookEntry::LEN];
        self.dapp.pack_into_slice(buf.as_mut_slice());
        bytes.extend_from_slice(&buf[..]);
        bytes.put_u16_le(self.num_instructions.as_u16());
        // appending the instructions to this vec could use too much memory
        // instead, we define the hash for a dapp transaction to be an iterated hash this way:
        // first, take the hash of everything in `bytes` up to this point:
        let mut result = hash(&bytes);
        // then, for each instruction, form a buffer with the previous hash followed by that
        // instruction, and then hash that
        let instructions = self.instructions()?;
        for instruction in instructions.into_iter() {
            let mut instruction_buffer: Vec<u8> = Vec::new();
            instruction_buffer.extend_from_slice(result.as_ref());
            append_instruction(&instruction, &mut instruction_buffer);
            result = hash(&instruction_buffer);
        }

        Ok(result)
    }

    pub fn instructions(&self) -> Result<Vec<Instruction>, ProgramError> {
        let read_nth_instruction = |index| -> Result<Instruction, ProgramError> {
            let instruction_offset = self.instruction_offsets.get(usize::from(index)).unwrap();
            if *instruction_offset == 0 {
                return Err(WalletError::OperationNotInitialized.into());
            }
            let offset = usize::from(instruction_offset - 1);
            read_instruction_from_slice(&self.instruction_data[offset..])
        };

        (0..self.num_instructions)
            .map(read_nth_instruction)
            .collect()
    }
}

impl Sealed for DAppMultisigData {}

impl IsInitialized for DAppMultisigData {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Pack for DAppMultisigData {
    const LEN: usize = 1
        + PUBKEY_BYTES
        + 32
        + DAppBookEntry::LEN
        + 1
        + 2 * MAX_INSTRUCTION_COUNT
        + 2
        + INSTRUCTION_DATA_LEN;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, DAppMultisigData::LEN];
        let (
            is_initialized_dst,
            wallet_address_dst,
            account_guid_hash_dst,
            dapp_dst,
            num_instructions_dst,
            instruction_offsets_dst,
            position_dst,
            instruction_data_dst,
        ) = mut_array_refs![
            dst,
            1,
            PUBKEY_BYTES,
            32,
            DAppBookEntry::LEN,
            1,
            2 * MAX_INSTRUCTION_COUNT,
            2,
            INSTRUCTION_DATA_LEN
        ];

        let DAppMultisigData {
            is_initialized,
            wallet_address,
            account_guid_hash,
            dapp,
            num_instructions,
            instruction_offsets,
            position,
            instruction_data,
        } = self;

        is_initialized_dst[0] = *is_initialized as u8;
        *wallet_address_dst = wallet_address.to_bytes();
        account_guid_hash_dst.copy_from_slice(account_guid_hash.to_bytes());
        dapp.pack_into_slice(dapp_dst);
        num_instructions_dst[0] = *num_instructions;
        instruction_offsets_dst
            .chunks_exact_mut(2)
            .take(MAX_INSTRUCTION_COUNT)
            .enumerate()
            .for_each(|(i, chunk)| {
                chunk.copy_from_slice(&instruction_offsets[i].to_le_bytes()[..2]);
            });
        instruction_data_dst.copy_from_slice(instruction_data);
        position_dst.copy_from_slice(&position.as_u16().to_le_bytes()[..2]);
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, DAppMultisigData::LEN];
        let (
            is_initialized,
            wallet_address,
            account_guid_hash,
            dapp,
            num_instructions,
            instruction_offsets,
            position,
            instruction_data,
        ) = array_refs![
            src,
            1,
            PUBKEY_BYTES,
            32,
            DAppBookEntry::LEN,
            1,
            2 * MAX_INSTRUCTION_COUNT,
            2,
            INSTRUCTION_DATA_LEN
        ];

        let is_initialized = match is_initialized {
            [0] => false,
            [1] => true,
            _ => return Err(ProgramError::InvalidAccountData),
        };

        let mut instruction_offsets_array: [u16; MAX_INSTRUCTION_COUNT] =
            [0; MAX_INSTRUCTION_COUNT];

        instruction_offsets
            .chunks_exact(2)
            .enumerate()
            .for_each(|(i, chunk)| {
                instruction_offsets_array[i] = u16::from_le_bytes([chunk[0], chunk[1]])
            });

        let wallet_address = Pubkey::new_from_array(*wallet_address);
        let account_guid_hash = BalanceAccountGuidHash::new(account_guid_hash);
        let dapp = DAppBookEntry::unpack_from_slice(dapp).unwrap();

        Ok(DAppMultisigData {
            is_initialized,
            wallet_address,
            account_guid_hash,
            dapp,
            num_instructions: num_instructions[0],
            instruction_offsets: instruction_offsets_array,
            instruction_data: instruction_data[..].to_owned(),
            position: usize::from(u16::from_le_bytes(*position)),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::constants::{HASH_LEN, PUBKEY_BYTES};
    use crate::model::address_book::{DAppBookEntry, DAppBookEntryNameHash};
    use crate::model::balance_account::BalanceAccountGuidHash;
    use crate::model::dapp_multisig_data::{DAppMultisigData, INSTRUCTION_DATA_LEN};
    use arrayref::array_ref;
    use sha2::Digest;
    use sha2::Sha256;
    use solana_program::program_pack::Pack;
    use solana_program::pubkey::Pubkey;

    fn hash_of(data: &[u8]) -> [u8; HASH_LEN] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash_output = hasher.finalize();
        *array_ref![hash_output, 0, HASH_LEN]
    }

    #[test]
    fn test_pack_unpack_empty() {
        let data = DAppMultisigData {
            is_initialized: false,
            wallet_address: Pubkey::new(&[0; PUBKEY_BYTES]),
            account_guid_hash: BalanceAccountGuidHash::new(&[0; HASH_LEN]),
            dapp: DAppBookEntry {
                address: Pubkey::new(&[0; PUBKEY_BYTES]),
                name_hash: DAppBookEntryNameHash::new(&[0; HASH_LEN]),
            },
            num_instructions: 0,
            instruction_offsets: [0; 32],
            position: 0,
            instruction_data: vec![0; INSTRUCTION_DATA_LEN],
        };
        let mut buffer = vec![0; DAppMultisigData::LEN];
        data.pack_into_slice(&mut buffer);
        let data2 = DAppMultisigData::unpack_from_slice(&buffer).unwrap();
        compare_data(data, data2);
    }

    #[test]
    fn test_pack_unpack_initialized() {
        let data = DAppMultisigData {
            is_initialized: true,
            wallet_address: Pubkey::new_unique(),
            account_guid_hash: BalanceAccountGuidHash::new(&hash_of(b"account-guid")),
            dapp: DAppBookEntry {
                address: Pubkey::new_unique(),
                name_hash: DAppBookEntryNameHash::new(&hash_of(b"dapp-name")),
            },
            num_instructions: 3,
            instruction_offsets: [
                1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            position: 23,
            instruction_data: vec![1; INSTRUCTION_DATA_LEN],
        };
        let mut buffer = vec![0; DAppMultisigData::LEN];
        data.pack_into_slice(&mut buffer);
        let data2 = DAppMultisigData::unpack_from_slice(&buffer).unwrap();
        compare_data(data, data2);
    }

    fn compare_data(data: DAppMultisigData, data2: DAppMultisigData) {
        assert_eq!(data.is_initialized, data2.is_initialized);
        assert_eq!(
            data.wallet_address.to_bytes(),
            data2.wallet_address.to_bytes()
        );
        assert_eq!(
            data.account_guid_hash.to_bytes(),
            data2.account_guid_hash.to_bytes()
        );
        assert_eq!(data.dapp.address.to_bytes(), data2.dapp.address.to_bytes());
        assert_eq!(
            data.dapp.name_hash.to_bytes(),
            data2.dapp.name_hash.to_bytes()
        );
        assert_eq!(data.num_instructions, data2.num_instructions);
        assert_eq!(data.instruction_offsets, data2.instruction_offsets);
        assert_eq!(data.instruction_data, data2.instruction_data);
        assert_eq!(data.position, data2.position);
    }
}
