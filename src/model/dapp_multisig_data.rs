use crate::error::WalletError;
use crate::instruction::read_instruction_from_slice;
use crate::model::address_book::{DAppBookEntry, DAppBookEntryNameHash};
use crate::model::balance_account::BalanceAccountGuidHash;
use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use bitvec::macros::internal::funty::Fundamental;
use bytes::BufMut;
use solana_program::entrypoint::ProgramResult;
use solana_program::hash::{hash, Hash};
use solana_program::instruction::Instruction;
use solana_program::msg;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{IsInitialized, Pack, Sealed};
use solana_program::pubkey::{Pubkey, PUBKEY_BYTES};

const INSTRUCTION_DATA_LEN: usize = 2500;

#[derive(Debug)]
pub struct DAppMultisigData {
    pub is_initialized: bool,
    pub wallet_address: Pubkey,
    pub account_guid_hash: BalanceAccountGuidHash,
    pub dapp: DAppBookEntry,
    pub total_instruction_len: u16,
    pub total_received_len: u16,
    instruction_data: Vec<u8>,
}

impl Default for DAppMultisigData {
    fn default() -> Self {
        DAppMultisigData {
            is_initialized: false,
            wallet_address: Pubkey::default(),
            account_guid_hash: BalanceAccountGuidHash::default(),
            dapp: DAppBookEntry {
                address: Pubkey::default(),
                name_hash: DAppBookEntryNameHash::zero(),
            },
            total_received_len: 0,
            total_instruction_len: 0,
            instruction_data: vec![],
        }
    }
}

impl DAppMultisigData {
    pub fn init(
        &mut self,
        wallet_address: Pubkey,
        account_guid_hash: BalanceAccountGuidHash,
        dapp: DAppBookEntry,
        total_instruction_len: u16,
    ) -> ProgramResult {
        self.is_initialized = true;
        self.wallet_address = wallet_address;
        self.account_guid_hash = account_guid_hash;
        self.dapp = dapp;
        if total_instruction_len > INSTRUCTION_DATA_LEN as u16 {
            return Err(WalletError::DAppInstructionOverflow.into());
        }
        self.total_instruction_len = total_instruction_len;
        self.total_received_len = 0;
        self.instruction_data = vec![0; INSTRUCTION_DATA_LEN];

        Ok(())
    }

    pub fn add_instruction(
        &mut self,
        instruction_data_offset: u16,
        instruction_data_len: u16,
        instruction_data: &Vec<u8>,
    ) -> ProgramResult {
        if self.is_initialized {
            let end_position = instruction_data_offset + instruction_data_len;
            if end_position > self.total_instruction_len {
                msg!(
                    "Offset {:} + size {:} too large (> {:})",
                    instruction_data_offset,
                    instruction_data_len,
                    self.total_instruction_len
                );
                return Err(WalletError::DAppInstructionOverflow.into());
            }
            if !self.instruction_data[instruction_data_offset as usize..end_position as usize]
                .into_iter()
                .all(|&byte| byte == 0)
            {
                return Err(WalletError::DAppInstructionAlreadySupplied.into());
            }
            self.instruction_data[instruction_data_offset as usize..end_position as usize]
                .copy_from_slice(instruction_data);
            self.total_received_len += instruction_data_len;
        }
        Ok(())
    }

    pub fn all_instructions_supplied(&self) -> bool {
        self.total_instruction_len == self.total_received_len
    }

    pub fn hash(&self, common_data: Vec<u8>) -> Result<Hash, ProgramError> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(7);
        bytes.extend_from_slice(common_data.as_slice());
        bytes.extend_from_slice(&self.wallet_address.to_bytes());
        bytes.extend_from_slice(&self.account_guid_hash.to_bytes());
        let mut buf = vec![0; DAppBookEntry::LEN];
        self.dapp.pack_into_slice(buf.as_mut_slice());
        bytes.extend_from_slice(&buf[..]);
        bytes.put_u16_le(self.total_instruction_len);
        bytes.extend_from_slice(
            self.instruction_data[0..self.total_instruction_len as usize].as_ref(),
        );

        Ok(hash(&bytes))
    }

    pub fn instructions(&self) -> Result<Vec<Instruction>, ProgramError> {
        let mut instructions_vec: Vec<Instruction> = Vec::new();
        let mut current_offset: usize = 0;
        if self.total_instruction_len != self.total_received_len {
            return Err(WalletError::OperationNotInitialized.into());
        }
        while current_offset < self.total_instruction_len as usize {
            let (instruction, instruction_len) =
                read_instruction_from_slice(&self.instruction_data[current_offset..]).unwrap();
            current_offset += instruction_len;
            instructions_vec.push(instruction)
        }

        Ok(instructions_vec)
    }
}

impl Sealed for DAppMultisigData {}

impl IsInitialized for DAppMultisigData {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Pack for DAppMultisigData {
    const LEN: usize = 1 + PUBKEY_BYTES + 32 + DAppBookEntry::LEN + 2 + 2 + INSTRUCTION_DATA_LEN;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, DAppMultisigData::LEN];
        let (
            is_initialized_dst,
            wallet_address_dst,
            account_guid_hash_dst,
            dapp_dst,
            total_instruction_len_dst,
            total_received_len_dst,
            instruction_data_dst,
        ) = mut_array_refs![
            dst,
            1,
            PUBKEY_BYTES,
            32,
            DAppBookEntry::LEN,
            2,
            2,
            INSTRUCTION_DATA_LEN
        ];

        let DAppMultisigData {
            is_initialized,
            wallet_address,
            account_guid_hash,
            dapp,
            total_instruction_len,
            total_received_len,
            instruction_data,
        } = self;

        is_initialized_dst[0] = *is_initialized as u8;
        *wallet_address_dst = wallet_address.to_bytes();
        account_guid_hash_dst.copy_from_slice(account_guid_hash.to_bytes());
        dapp.pack_into_slice(dapp_dst);
        total_instruction_len_dst
            .copy_from_slice(&total_instruction_len.as_u16().to_le_bytes()[..2]);
        total_received_len_dst.copy_from_slice(&total_received_len.as_u16().to_le_bytes()[..2]);
        instruction_data_dst.copy_from_slice(instruction_data);
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, DAppMultisigData::LEN];
        let (
            is_initialized,
            wallet_address,
            account_guid_hash,
            dapp,
            total_instruction_len,
            total_received_len,
            instruction_data,
        ) = array_refs![
            src,
            1,
            PUBKEY_BYTES,
            32,
            DAppBookEntry::LEN,
            2,
            2,
            INSTRUCTION_DATA_LEN
        ];

        let is_initialized = match is_initialized {
            [0] => false,
            [1] => true,
            _ => return Err(ProgramError::InvalidAccountData),
        };

        let wallet_address = Pubkey::new_from_array(*wallet_address);
        let account_guid_hash = BalanceAccountGuidHash::new(account_guid_hash);
        let dapp = DAppBookEntry::unpack_from_slice(dapp).unwrap();
        let total_instruction_len = u16::from_le_bytes(*total_instruction_len);
        let total_received_len = u16::from_le_bytes(*total_received_len);

        Ok(DAppMultisigData {
            is_initialized,
            wallet_address,
            account_guid_hash,
            dapp,
            total_instruction_len,
            total_received_len,
            instruction_data: instruction_data[..].to_owned(),
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
            total_instruction_len: 0,
            total_received_len: 0,
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
            total_instruction_len: 100,
            total_received_len: 102,
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
        assert_eq!(data.total_instruction_len, data2.total_instruction_len);
        assert_eq!(data.total_received_len, data2.total_received_len);
        assert_eq!(data.instruction_data, data2.instruction_data);
    }
}
