use crate::constants::{HASH_LEN, VERSION_LEN};
use crate::error::WalletError;
use crate::handlers::utils::next_program_account_info;
use crate::model::address_book::{AddressBook, DAppBook};
use crate::model::signer::NamedSigner;
use crate::model::wallet::{
    Approvers, BalanceAccounts, NamedSigners, Signers, Wallet, WalletGuidHash,
};
use crate::utils::SlotId;
use crate::version::{Versioned, VERSION};
use arrayref::{array_ref, array_refs};
use itertools::Itertools;
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::Pack;
use solana_program::pubkey::{Pubkey, PUBKEY_BYTES};
use std::collections::BTreeMap;
use std::time::Duration;

type MigrationFunction = fn(&[u8], &mut [u8], &Pubkey);

static MIGRATION_TEST_VERSION: u32 = VERSION;

// this is a test migration which goes from the current version to version 0, and
// simply copies all the data
fn migration_test(source: &[u8], destination: &mut [u8], rent_return: &Pubkey) {
    let source_account = Wallet::unpack(source).unwrap();
    let destination_account = Wallet {
        is_initialized: true,
        version: 0,
        rent_return: *rent_return,
        wallet_guid_hash: source_account.wallet_guid_hash,
        signers: source_account.signers,
        address_book: source_account.address_book,
        approvals_required_for_config: source_account.approvals_required_for_config,
        approval_timeout_for_config: source_account.approval_timeout_for_config,
        config_approvers: source_account.config_approvers,
        balance_accounts: source_account.balance_accounts,
        dapp_book: source_account.dapp_book,
    };
    Wallet::pack(destination_account, destination).unwrap();
}

const V2_WALLET_SIZE: usize = 8694;

fn v2_to_v3_add_name_to_signers(source: &[u8], destination: &mut [u8], rent_return: &Pubkey) {
    let src = array_ref![source, 0, V2_WALLET_SIZE];
    let (
        is_initialized,
        _,
        _,
        wallet_guid_hash,
        signers_src,
        address_book_src,
        approvals_required_for_config,
        approval_timeout_for_config,
        config_approvers_src,
        dapp_book_src,
        balance_accounts_src,
    ) = array_refs![
        src,
        1,
        VERSION_LEN,
        PUBKEY_BYTES,
        HASH_LEN,
        Signers::LEN,
        AddressBook::LEN,
        1,
        8,
        Approvers::STORAGE_SIZE,
        DAppBook::LEN,
        BalanceAccounts::LEN
    ];

    let signers = Signers::unpack_from_slice(signers_src).unwrap();
    let mut named_signers = NamedSigners::new();
    named_signers.insert_many(
        &signers
            .filled_slots()
            .into_iter()
            .map(|s| {
                (
                    SlotId::new(s.0.value),
                    NamedSigner {
                        key: s.1.key,
                        name_hash: [0; HASH_LEN],
                    },
                )
            })
            .collect_vec(),
    );
    let destination_account = Wallet {
        is_initialized: match is_initialized {
            [0] => false,
            _ => true,
        },
        version: 3,
        rent_return: *rent_return,
        wallet_guid_hash: WalletGuidHash::new(wallet_guid_hash),
        signers: named_signers,
        address_book: AddressBook::unpack_from_slice(address_book_src).unwrap(),
        approvals_required_for_config: approvals_required_for_config[0],
        approval_timeout_for_config: Duration::from_secs(u64::from_le_bytes(
            *approval_timeout_for_config,
        )),
        config_approvers: Approvers::new(*config_approvers_src),
        balance_accounts: BalanceAccounts::unpack_from_slice(balance_accounts_src).unwrap(),
        dapp_book: DAppBook::unpack_from_slice(dapp_book_src).unwrap(),
    };
    Wallet::pack(destination_account, destination).unwrap();
}

fn migrations() -> BTreeMap<u32, MigrationFunction> {
    BTreeMap::from([
        (MIGRATION_TEST_VERSION, migration_test as MigrationFunction),
        (2, v2_to_v3_add_name_to_signers as MigrationFunction),
    ])
}

pub fn handle(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let source_account_info = next_program_account_info(accounts_iter, program_id)?;
    let destination_account_info = next_program_account_info(accounts_iter, program_id)?;
    let rent_return_account_info = next_account_info(accounts_iter)?;

    let source_version = Wallet::version_from_slice(&source_account_info.data.borrow())?;
    if source_version == VERSION {
        return Err(WalletError::AccountVersionMismatch.into());
    }

    if Wallet::is_initialized_from_slice(&destination_account_info.data.borrow()) {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    if let Some(migrator) = migrations().get(&source_version) {
        migrator(
            &source_account_info.data.borrow(),
            &mut destination_account_info.data.borrow_mut(),
            rent_return_account_info.key,
        );
        Ok(())
    } else {
        Err(WalletError::UnknownVersion.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::signer::{NamedSigner, Signer};
    use crate::utils::SlotId;
    use arrayref::{array_mut_ref, mut_array_refs};
    use solana_program::program_pack::{IsInitialized, Sealed};

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct WalletV2 {
        pub is_initialized: bool,
        pub version: u32,
        pub rent_return: Pubkey,
        pub wallet_guid_hash: WalletGuidHash,
        pub signers: Signers,
        pub address_book: AddressBook,
        pub approvals_required_for_config: u8,
        pub approval_timeout_for_config: Duration,
        pub config_approvers: Approvers,
        pub balance_accounts: BalanceAccounts,
        pub dapp_book: DAppBook,
    }

    impl Sealed for WalletV2 {}

    impl IsInitialized for WalletV2 {
        fn is_initialized(&self) -> bool {
            self.is_initialized
        }
    }

    impl WalletV2 {
        fn pack_into_slice(&self, dst: &mut [u8]) {
            let dst = array_mut_ref![dst, 0, V2_WALLET_SIZE];
            let (
                is_initialized_dst,
                version_dst,
                rent_return_dst,
                wallet_guid_hash_dst,
                signers_dst,
                address_book_dst,
                approvals_required_for_config_dst,
                approval_timeout_for_config_dst,
                config_approvers_dst,
                dapp_book_dst,
                balance_accounts_dst,
            ) = mut_array_refs![
                dst,
                1,
                VERSION_LEN,
                PUBKEY_BYTES,
                HASH_LEN,
                Signers::LEN,
                AddressBook::LEN,
                1,
                8,
                Approvers::STORAGE_SIZE,
                DAppBook::LEN,
                BalanceAccounts::LEN
            ];

            is_initialized_dst[0] = self.is_initialized as u8;
            *version_dst = self.version.to_le_bytes();
            rent_return_dst.copy_from_slice(self.rent_return.as_ref());
            wallet_guid_hash_dst.copy_from_slice(&self.wallet_guid_hash.to_bytes());
            self.signers.pack_into_slice(signers_dst);
            self.address_book.pack_into_slice(address_book_dst);
            approvals_required_for_config_dst[0] = self.approvals_required_for_config;
            *approval_timeout_for_config_dst =
                self.approval_timeout_for_config.as_secs().to_le_bytes();
            config_approvers_dst.copy_from_slice(self.config_approvers.as_bytes());
            self.dapp_book.pack_into_slice(dapp_book_dst);
            self.balance_accounts.pack_into_slice(balance_accounts_dst);
        }
    }

    #[test]
    fn test_v2_to_v3_add_signer_name_hash() {
        let v2_wallet = WalletV2 {
            is_initialized: true,
            version: 2,
            rent_return: Pubkey::new_unique(),
            wallet_guid_hash: WalletGuidHash::new(&Pubkey::new_unique().to_bytes()),
            signers: Signers::from_vec(vec![
                (SlotId::new(0), Signer::new(Pubkey::new_unique())),
                (SlotId::new(1), Signer::new(Pubkey::new_unique())),
                (SlotId::new(2), Signer::new(Pubkey::new_unique())),
            ]),
            address_book: AddressBook::new(),
            approvals_required_for_config: 1,
            approval_timeout_for_config: Duration::from_secs(600),
            config_approvers: Approvers::from_enabled_vec(vec![SlotId::new(0), SlotId::new(1)]),
            balance_accounts: BalanceAccounts::new(),
            dapp_book: DAppBook::from_vec(vec![]),
        };

        let mut v2_wallet_data = vec![0; V2_WALLET_SIZE];
        v2_wallet.pack_into_slice(v2_wallet_data.as_mut_slice());

        let mut v3_wallet_data = vec![0; V2_WALLET_SIZE + (32 * Wallet::MAX_SIGNERS)];

        let v3_rent_return = Pubkey::new_unique();

        v2_to_v3_add_name_to_signers(
            &*v2_wallet_data,
            v3_wallet_data.as_mut_slice(),
            &v3_rent_return,
        );

        let v3_wallet = Wallet::unpack_from_slice(v3_wallet_data.as_slice()).unwrap();

        assert_eq!(3, v3_wallet.version);
        assert_eq!(v3_rent_return, v3_wallet.rent_return);
        assert_eq!(v2_wallet.wallet_guid_hash, v3_wallet.wallet_guid_hash);
        assert_eq!(
            v2_wallet
                .signers
                .into_iter()
                .map(|s| NamedSigner {
                    key: s.key,
                    name_hash: [0; 32]
                })
                .collect::<Vec<NamedSigner>>(),
            v3_wallet.signers.into_iter().collect::<Vec<NamedSigner>>()
        );
        assert_eq!(v2_wallet.address_book, v3_wallet.address_book);
        assert_eq!(
            v2_wallet.approvals_required_for_config,
            v3_wallet.approvals_required_for_config
        );
        assert_eq!(
            v2_wallet.approval_timeout_for_config,
            v3_wallet.approval_timeout_for_config
        );
        assert_eq!(v2_wallet.config_approvers, v3_wallet.config_approvers);
        assert_eq!(v2_wallet.balance_accounts, v3_wallet.balance_accounts);
        assert_eq!(v2_wallet.dapp_book, v3_wallet.dapp_book);
    }
}
