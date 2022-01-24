use std::iter::Map;
use std::ops::Index;
use itertools::Itertools;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{Pack, Sealed};
use std::marker::PhantomData;
use bitvec::prelude::*;
use bitvec::slice::IterOnes;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SlotId<A> {
    pub value: usize,
    item_type: PhantomData<A>
}

impl<A> SlotId<A> {
    pub fn new(id: usize) -> Self {
        Self { value: id, item_type: PhantomData }
    }
}

#[derive(Debug, Clone)]
pub struct Slots<A, const SIZE: usize> {
    pub array: Box<[Option<A>; SIZE]>,
}

impl<A, const SIZE: usize> Index<SlotId<A>> for Slots<A, SIZE> {
    type Output = Option<A>;

    fn index(&self, r: SlotId<A>) -> &Self::Output {
        &self.array[r.value]
    }
}

impl<A: Copy + PartialEq + Ord, const SIZE: usize> Slots<A, SIZE> {
    pub const FLAGS_STORAGE_SIZE: usize = bitvec::mem::elts::<u8>(SIZE);

    pub fn new() -> Slots<A, SIZE> {
        Slots { array: Box::new([None; SIZE]) }
    }

    pub fn insert(&mut self, id: SlotId<A>, item: A) {
        match self[id] {
            Some(slot_item) => {
                if slot_item != item {
                    panic!("Failed inserting: slot is already taken");
                }
            },
            None => {
                self.array[id.value] = Some(item)
            }
        }
    }

    pub fn can_be_inserted(&self, items: &Vec<(SlotId<A>, A)>) -> bool {
        items.iter().all(|(id, value)| id.value < SIZE && (self[*id] == None || self[*id] == Some(*value)))
    }

    pub fn insert_many(&mut self, items: &Vec<(SlotId<A>, A)>) {
        for (slot_id, value) in items {
            self.insert(*slot_id, *value);
        }
    }

    pub fn contains(&self, items: &Vec<(SlotId<A>, A)>) -> bool {
        for (id, value) in items {
            if id.value >= SIZE || self[*id] != Some(*value) {
                return false
            }
        }
        return true
    }

    pub fn remove(&mut self, id: SlotId<A>, item: A) {
        for slot_item in self[id] {
            if slot_item != item {
                panic!("Failed removing: unexpected item in slot");
            } else {
                self.array[id.value] = None;
            }
        }
    }

    pub fn can_be_removed(&self, items: &Vec<(SlotId<A>, A)>) -> bool {
        items.iter().all(|(id, value)| id.value < SIZE && (self[*id] == None || self[*id] == Some(*value)))
    }

    pub fn remove_many(&mut self, items: &Vec<(SlotId<A>, A)>) {
        for (slot_id, value) in items {
            self.remove(*slot_id, *value);
        }
    }

    pub fn find_id(&self, value: &A) -> Option<SlotId<A>> {
        self.array
            .iter()
            .position(|value_opt| *value_opt == Some(*value))
            .map(|pos| SlotId::new(usize::from(pos)))
    }
}

impl<A, const SIZE: usize> Sealed for Slots<A, SIZE> {}

impl<A: Pack + Copy + PartialEq + Ord, const SIZE: usize> Pack for Slots<A, SIZE> {
    const LEN: usize = SIZE * (1 + A::LEN);

    fn pack_into_slice(&self, dst: &mut [u8]) {
        dst.fill(0);
        for (i, chunk) in dst.chunks_exact_mut(1 + A::LEN).enumerate() {
            for item in self.array[i].as_ref() {
                chunk[0] = 1;
                item.pack_into_slice(&mut chunk[1..1 + A::LEN]);
            }
        }
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let mut res = Slots::new();

        for (i, chunk) in src.chunks_exact(1 + A::LEN).enumerate() {
            if chunk[0] == 0 {
                res.array[i] = None;
            } else {
                res.array[i] = Some(A::unpack_from_slice(&chunk[1..1 + A::LEN])?);
            };
        }

        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct SlotFlags<A, const STORAGE_SIZE: usize> {
    bit_arr: BitArray<[u8; STORAGE_SIZE]>,
    item_type: PhantomData<A>
}

pub type IterEnabledIds<'a, A> = Map<IterOnes<'a, u8, Lsb0>, fn(usize) -> SlotId<A>>;

impl<A, const STORAGE_SIZE: usize> SlotFlags<A, STORAGE_SIZE> {
    pub const STORAGE_SIZE: usize = STORAGE_SIZE;

    pub fn new(data: [u8; STORAGE_SIZE]) -> Self {
        Self { bit_arr: BitArray::new(data), item_type: PhantomData }
    }

    pub fn zero() -> Self {
        Self::new([0; STORAGE_SIZE])
    }

    pub fn enable(&mut self, id: &SlotId<A>) {
        self.bit_arr.set(id.value, true);
    }

    pub fn enable_many(&mut self, ids: &Vec<&SlotId<A>>) {
        for id in ids {
            self.enable(id);
        }
    }

    pub fn disable(&mut self, id: &SlotId<A>) {
        self.bit_arr.set(id.value, false);
    }

    pub fn is_enabled(&self, id: &SlotId<A>) -> bool {
        self.bit_arr[id.value]
    }

    pub fn any_enabled(&self, ids: &Vec<&SlotId<A>>) -> bool {
        ids.iter().any(|r| self.bit_arr[r.value])
    }

    pub fn count_enabled(&self) -> usize {
        self.bit_arr.count_ones()
    }

    pub fn iter_enabled(&self) -> IterEnabledIds<A> {
        self.bit_arr.iter_ones().map(SlotId::<A>::new)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bit_arr.as_raw_slice()
    }
}

pub trait GetSlotIds<A> {
    fn slot_ids(&self) -> Vec<&SlotId<A>>;
}

impl<A> GetSlotIds<A> for Vec<(SlotId<A>, A)> {
    fn slot_ids(&self) -> Vec<&SlotId<A>> {
        self.iter().map(|(slot_id, _)| slot_id).collect_vec()
    }
}
