use solana_program::program_error::ProgramError;

pub static VERSION: u32 = 4;

pub trait Versioned {
    fn version_from_slice(src: &[u8]) -> Result<u32, ProgramError>;
}
