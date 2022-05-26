use std::convert::TryInto;
use std::slice::Iter;
use std::time::Duration;

use crate::constants::HASH_LEN;
use crate::model::address_book::AddressBookEntryNameHash;
use crate::model::balance_account::{BalanceAccountGuidHash, BalanceAccountNameHash};
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{IsInitialized, Pack};

pub fn pack_option<T>(option: Option<&T>, dst: &mut Vec<u8>)
where
    T: Pack + Default + Clone,
{
    let mut buf: Vec<u8> = Vec::with_capacity(T::LEN);
    buf.resize(T::LEN, 0);
    if let Some(value) = option {
        dst.push(1);
        Pack::pack(value.clone(), buf.as_mut_slice()).unwrap();
    } else {
        dst.push(0);
        Pack::pack(T::default(), buf.as_mut_slice()).unwrap();
    }
    dst.extend_from_slice(&buf);
}

pub fn unpack_option<T>(iter: &mut Iter<u8>) -> Result<Option<T>, ProgramError>
where
    T: Pack + IsInitialized,
{
    if let Some(has_value) = iter.next() {
        let value_data = read_slice(iter, T::LEN)
            .ok_or(ProgramError::InvalidInstructionData)
            .unwrap();
        Ok(if *has_value == 0 {
            None
        } else {
            Some(T::unpack(value_data)?)
        })
    } else {
        Err(ProgramError::InvalidInstructionData)
    }
}

pub fn read_slice<'a>(iter: &'a mut Iter<u8>, size: usize) -> Option<&'a [u8]> {
    let slice = iter.as_slice().get(0..size);
    if slice.is_some() {
        for _ in 0..size {
            iter.next();
        }
    }
    return slice;
}

pub fn read_optional_u8(iter: &mut Iter<u8>) -> Result<Option<u8>, ProgramError> {
    if let Some(has_value) = iter.next() {
        Ok(if *has_value == 0 {
            iter.next();
            None
        } else {
            iter.next().map(|v| *v)
        })
    } else {
        Err(ProgramError::InvalidInstructionData)
    }
}

pub fn append_optional_u8(maybe_u8: &Option<u8>, dst: &mut Vec<u8>) {
    if let Some(value) = maybe_u8 {
        dst.push(1);
        dst.push(*value);
    } else {
        dst.push(0);
        dst.push(0);
    }
}

pub fn read_u8<'a, 'b>(iter: &'a mut Iter<'b, u8>) -> Option<&'b u8> {
    iter.next()
}

pub fn read_u16(iter: &mut Iter<u8>) -> Option<u16> {
    read_fixed_size_array::<2>(iter).map(|slice| u16::from_le_bytes(*slice))
}

pub fn read_u64(iter: &mut Iter<u8>) -> Option<u64> {
    read_fixed_size_array::<8>(iter).map(|slice| u64::from_le_bytes(*slice))
}

pub fn read_account_guid_hash(iter: &mut Iter<u8>) -> Option<BalanceAccountGuidHash> {
    read_fixed_size_array::<HASH_LEN>(iter).map(|slice| BalanceAccountGuidHash::new(&*slice))
}

pub fn read_account_name_hash(iter: &mut Iter<u8>) -> Option<BalanceAccountNameHash> {
    read_fixed_size_array::<HASH_LEN>(iter).map(|slice| BalanceAccountNameHash::new(&*slice))
}

pub fn read_address_book_entry_name_hash(iter: &mut Iter<u8>) -> Option<AddressBookEntryNameHash> {
    read_fixed_size_array::<HASH_LEN>(iter).map(|slice| AddressBookEntryNameHash::new(&*slice))
}

pub fn read_fixed_size_array<'a, const SIZE: usize>(
    iter: &'a mut Iter<u8>,
) -> Option<&'a [u8; SIZE]> {
    read_slice(iter, SIZE).and_then(|slice| slice.try_into().ok())
}

pub fn read_duration(iter: &mut Iter<u8>) -> Option<Duration> {
    read_fixed_size_array::<8>(iter).map(|slice| Duration::from_secs(u64::from_le_bytes(*slice)))
}

pub fn append_duration(duration: &Duration, dst: &mut Vec<u8>) {
    dst.extend_from_slice(&duration.as_secs().to_le_bytes()[..])
}

pub fn read_optional_duration(iter: &mut Iter<u8>) -> Result<Option<Duration>, ProgramError> {
    if let Some(has_value) = iter.next() {
        let value_data = read_fixed_size_array::<8>(iter)
            .ok_or(ProgramError::InvalidInstructionData)
            .unwrap();
        Ok(if *has_value == 0 {
            None
        } else {
            Some(Duration::from_secs(u64::from_le_bytes(*value_data)))
        })
    } else {
        Err(ProgramError::InvalidInstructionData)
    }
}

pub fn append_optional_duration(maybe_duration: &Option<Duration>, dst: &mut Vec<u8>) {
    if let Some(duration) = maybe_duration {
        dst.push(1);
        dst.extend_from_slice(&duration.as_secs().to_le_bytes()[..]);
    } else {
        dst.push(0);
        let mut buf: Vec<u8> = Vec::with_capacity(8);
        buf.resize(8, 0);
        dst.extend_from_slice(&buf);
    }
}
