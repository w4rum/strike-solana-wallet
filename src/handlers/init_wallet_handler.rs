use crate::handlers::utils::{next_program_account_info, next_signer_account_info};
use crate::instruction::InitialWalletConfig;
use crate::model::wallet::{Wallet, WalletGuidHash};
use crate::version::VERSION;
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::bpf_loader_upgradeable::UpgradeableLoaderState;
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::{IsInitialized, Pack};
use solana_program::pubkey::Pubkey;
use solana_program::{bpf_loader_upgradeable, msg};

pub fn handle(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    wallet_guid_hash: &WalletGuidHash,
    initial_config: &InitialWalletConfig,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let wallet_account_info = next_program_account_info(accounts_iter, program_id)?;
    let program_data_account_info = next_account_info(accounts_iter)?;
    let rent_return_account_info = next_signer_account_info(accounts_iter)?;
    let program_upgrade_authority_account_info = next_signer_account_info(accounts_iter)?;

    if *program_upgrade_authority_account_info.key
        != get_program_upgrade_authority(program_id, program_data_account_info)?
    {
        msg!("Has to be signed by program upgrade authority");
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut wallet = Wallet::unpack_unchecked(&wallet_account_info.data.borrow())?;

    if wallet.is_initialized() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    wallet.is_initialized = true;
    wallet.version = VERSION;
    wallet.rent_return = *rent_return_account_info.key;
    wallet.wallet_guid_hash = *wallet_guid_hash;
    wallet.initialize(initial_config)?;
    Wallet::pack(wallet, &mut wallet_account_info.data.borrow_mut())?;

    Ok(())
}

fn get_program_upgrade_authority(
    program_id: &Pubkey,
    program_data_account_info: &AccountInfo,
) -> Result<Pubkey, ProgramError> {
    let (program_data_account_address, _) =
        Pubkey::find_program_address(&[&program_id.to_bytes()], &bpf_loader_upgradeable::id());

    if program_data_account_address != *program_data_account_info.key {
        msg!("Wrong program data account address");
        return Err(ProgramError::InvalidArgument);
    }

    return if let Ok(UpgradeableLoaderState::ProgramData {
        slot: _,
        upgrade_authority_address,
    }) = bincode::deserialize(&program_data_account_info.data.borrow())
    {
        upgrade_authority_address.ok_or(ProgramError::InvalidArgument)
    } else {
        msg!("Failed to deserialize program data account");
        Err(ProgramError::InvalidArgument)
    };
}
