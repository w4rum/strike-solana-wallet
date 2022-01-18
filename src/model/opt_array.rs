use std::ops::Index;
use itertools::Itertools;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{Pack, Sealed};

#[derive(Debug)]
pub struct OptArray<A, const N: usize> {
    array: Box<[Option<A>; N]>
}

impl<A, const N: usize> Index<usize> for OptArray<A, N> {
    type Output = Option<A>;

    fn index(&self, i: usize) -> &Self::Output {
        &self.array[i]
    }
}

impl<A, const N: usize> OptArray<A, N> {
    pub fn from_vec(vec: Vec<Option<A>>) -> OptArray<A, N> {
        unsafe {
            // convert vector into a boxed array with static size
            OptArray { array: Box::from_raw(Box::into_raw(vec.into_boxed_slice()) as *mut [Option<A>; N]) }
        }
    }

    pub fn len_after_update(&self, add_items: &Vec<A>, remove_items: &Vec<A>) -> usize
        where
            A: Copy + PartialEq
    {
        let mut result = 0;
        for item in self.array.iter() {
            if item.is_some() && !remove_items.contains(&item.as_ref().unwrap()) {
                result += 1;
            }
        }
        for item_to_add in add_items.into_iter() {
            if !self.array.contains(&Some(*item_to_add)) {
                result += 1;
            }
        }
        result
    }

    pub fn add_items(&mut self, add_items: &Vec<A>)
        where
            A: Copy + PartialEq
    {
        let mut add_items = add_items.clone();

        for item_opt in self.array.iter_mut() {
            if add_items.is_empty() { break }
            if item_opt.is_none() {
                *item_opt = Some(*add_items.first().unwrap());
                add_items.swap_remove(0);
            }
        }
    }

    // returns indexes of the removed items
    pub fn remove_items(&mut self, remove_items: &Vec<A>) -> Vec<usize>
        where
            A: Copy + PartialEq
    {
        let mut remove_items = remove_items.clone();
        let mut removed_items = Vec::new();

        for (i, item_opt) in self.array.iter_mut().enumerate() {
            if remove_items.is_empty() { break }
            if item_opt.is_none() { continue }
            let item = item_opt.unwrap();

            for remove_item_idx in remove_items.iter().position(|it| it == &item) {
                *item_opt = None;
                remove_items.swap_remove(remove_item_idx);
                removed_items.push(i);
            }
        }

        removed_items
    }

    pub fn find_index(&self, item: &A) -> Option<usize>
        where
            A: Copy + PartialEq
    {
        self.array
            .iter()
            .position(|it| it == &Some(*item))
    }

    pub fn find_indexes(&self, items: &Vec<A>) -> Vec<usize>
        where
            A: Copy + PartialEq
    {
        return self.array
            .iter()
            .positions(|item_opt| item_opt.is_some() && items.contains(&item_opt.unwrap()))
            .collect_vec();
    }
}

impl<A, const N: usize> Sealed for OptArray<A, N> {}

impl<A: Pack, const N: usize> Pack for OptArray<A, N> {
    const LEN: usize = N * A::LEN;

    fn pack_into_slice(&self, dst: &mut [u8]) {
        dst.fill(0);
        for (i, chunk) in dst.chunks_exact_mut(A::LEN).enumerate() {
            for item in self.array[i].as_ref() {
                item.pack_into_slice(chunk);
            }
        }
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let mut vec = Vec::with_capacity(N);

        for chunk in src.chunks_exact(A::LEN) {
            vec.push(
                if chunk.iter().all(|&b| b == 0) {
                    None
                } else {
                    Some(A::unpack_from_slice(chunk)?)
                }
            );
        }

        Ok(OptArray::from_vec(vec))
    }
}
