use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;
use anchor_lang::solana_program::sysvar::clock::Clock;
use anchor_lang::solana_program::sysvar::instructions::{load_instruction_at_checked, ID as IX_ID};
use anchor_spl::{
    associated_token::AssociatedToken,
    token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked, CloseAccount},
};
pub mod utils;

declare_id!("HTVUaceNryrFRPGdWpsNZEya2qujTEi6xJbAoBVfVVs1");

// March 9 2025 11:59 pm, update on deployment.
const END_TIME: u32 = 1741564799;

const DISCIMINATOR_LEN: usize = 8;
const BUMP_SEED_OFFSET: usize = DISCIMINATOR_LEN; // Skip discriminator (8 bytes).
const OWNER_OFFSET: usize = BUMP_SEED_OFFSET + 1; // Skip bump seed (1 byte).
const CLAIM_SIGNER_OFFSET: usize = OWNER_OFFSET + 32; // Skip 32 bytes.
const BITMAP_LEN_OFFSET: usize = CLAIM_SIGNER_OFFSET + 32; // Skip claim signer.
const BITMAP_BYTES_OFFSET: usize = BITMAP_LEN_OFFSET + 4; // Skip bitmap length.
const INITIAL_STATE_BYTE_LEN: usize = BITMAP_BYTES_OFFSET + 128;
const EXTEND_BITMAP_BYTES_LEN: usize = 1000;

const STATE_SEED: &[u8] = b"state";

macro_rules! state_slice {
    ($ctx:expr, $start:expr, $n:expr) => {
        $ctx.accounts.state.data.borrow_mut()[$start..$start + $n]
    };
}

macro_rules! state_pubkey_slice {
    ($ctx:expr, $start:expr) => {
        state_slice!($ctx, $start, 32)
    };
}

macro_rules! state_pubkey {
    ($ctx:expr, $start:expr) => {
        Pubkey::new_from_array(state_pubkey_slice!($ctx, $start).try_into().unwrap())
    };
}

macro_rules! only_owner {
    ($ctx:expr) => {
        require!(
            $ctx.accounts.owner.key() == state_pubkey!($ctx, OWNER_OFFSET),
            CustomError::Unauthorized
        );
    };
}

macro_rules! state_claim_bitmap_byte {
    ($ctx:expr, $i:expr) => {
        // The program will panic if the state account doesn't have enough space.
        $ctx.accounts.state.data.borrow_mut()[BITMAP_BYTES_OFFSET + $i as usize]
    };
}

#[program]
pub mod token_claimer {
    use super::*;

    /// Initialize the program state.
    pub fn initialize(ctx: Context<Initialize>, claim_signer: Pubkey) -> Result<()> {
        *ctx.accounts.state = State {
            bump: ctx.bumps.state,
            owner: ctx.accounts.owner.key(),
            claim_signer,
            claimed_bitmap: Vec::new(),
        };
        Ok(())
    }

    /// Expands the bitmap Vec by 1000 bytes, resize limited due to use of realloc constraint.
    /// The realloc constraint automatically handles SOL transfer, but takes space on the instruction.
    /// Increasing EXTEND_BITMAP_BYTES_LEN above ~1500 causes following error:
    /// Error: memory allocation failed, out of memory
    pub fn expand_bitmap(ctx: Context<ExpandBitmap>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        let current_len = state.claimed_bitmap.len();
        state.claimed_bitmap.resize(current_len + EXTEND_BITMAP_BYTES_LEN, 0);
        Ok(())
    }

    /// Update the claim signer (only callable by the address specfied in owner field in account state).
    pub fn set_claim_signer(ctx: Context<SetClaimSigner>, new_claim_signer: Pubkey) -> Result<()> {
        let previous_claim_signer = ctx.accounts.state.claim_signer;
        ctx.accounts.state.claim_signer = new_claim_signer;

        emit!(ClaimSignerUpdated {
            previous_claim_signer,
            new_claim_signer,
        });

        Ok(())
    }

    /// Transfer "owner" of state account.
    pub fn transfer_ownership(ctx: Context<TransferOwnership>, new_owner: Pubkey) -> Result<()> {
        let previous_owner = ctx.accounts.state.owner;
        ctx.accounts.state.owner = new_owner;

        emit!(OwnershipTransferred {
            previous_owner,
            new_owner,
        });

        Ok(())
    }

    /// Process a claim for tokens with a valid signature.
    /// This requires an additional instruction message signed by the "claim signer" address.
    pub fn claim(
        ctx: Context<Claim>,
        claim_indices: Vec<u32>,
        total_amount: u64,
        expiry: u32,
    ) -> Result<()> {
        require!(
            Clock::get()?.unix_timestamp < expiry.into() && expiry <= END_TIME,
            CustomError::ClaimExpired
        );
        let solana_account_info = ctx.accounts.ix_sysvar.to_account_info();

        // recreate the message to verify against "claim signer" signature
        let message = keccak::hashv(&[
            keccak::hash(
                &claim_indices
                    .iter()
                    .flat_map(|index| index.to_le_bytes())
                    .collect::<Vec<u8>>(),
            )
            .as_ref(),
            ctx.accounts.claimer.key().as_ref(),
            ctx.accounts.source_token_account.key().as_ref(),
            ctx.accounts.destination_token_account.key().as_ref(),
            total_amount.to_le_bytes().as_slice(),
            expiry.to_le_bytes().as_slice(),
        ])
        .0;
        
        // Check instructions in the transaction to find/verify the signature by "claim signer"
        let mut i = 0;
        let mut has_valid_signature = false;
        while let Ok(ix) = load_instruction_at_checked(i, &solana_account_info) {
            if utils::verify_ed25519_ix(
                &ix,
                &state_pubkey_slice!(ctx, CLAIM_SIGNER_OFFSET),
                &message,
            ) {
                has_valid_signature = true;
                break;
            }
            i += 1;
        }
        require!(has_valid_signature, CustomError::InvalidSignature);

        for claim_index in claim_indices.iter() {
            // Check if the claim index has already been processed.
            let byte_index = claim_index >> 3; // Division by 8 (bit shift).
            let bit_mask = 1 << ((claim_index & 7) as u8); // Modulo 8 (bit mask).
            require!(
                state_claim_bitmap_byte!(ctx, byte_index) & bit_mask == 0,
                CustomError::AlreadyClaimed
            );
            // Mark the claim as processed.
            state_claim_bitmap_byte!(ctx, byte_index) |= bit_mask;
        }

        // Ensure there are enough tokens in the source account.
        require!(
            ctx.accounts.source_token_account.amount >= total_amount,
            CustomError::InsufficientFunds
        );

        // Transfer tokens from program owned token account to destination token account.
        let decimals = ctx.accounts.mint.decimals;
        let mint_address = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[mint_address.as_ref(), &[ctx.bumps.source_token_account]]];

        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.source_token_account.to_account_info(),
                to: ctx.accounts.destination_token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                authority: ctx.accounts.source_token_account.to_account_info(),
            },
        )
        .with_signer(signer_seeds);
        token_interface::transfer_checked(cpi_ctx, total_amount, decimals)?;

        emit!(ClaimProcessed {
            claimer: ctx.accounts.claimer.key(),
            claim_indices,
            total_amount,
        });

        Ok(())
    }

    /// Unset a claim index.
    pub fn unset_claim_indices(
        ctx: Context<UnsetClaimIndex>,
        claim_indices: Vec<u32>,
    ) -> Result<()> {
        only_owner!(ctx);

        for claim_index in claim_indices.iter() {
            let byte_index = claim_index >> 3; // Division by 8 (bit shift).
            let bit_mask = 1 << ((claim_index & 7) as u8); // Modulo 8 (bit mask).
            state_claim_bitmap_byte!(ctx, byte_index) &= !bit_mask;
        }

        Ok(())
    }

    /// Create a token account for the program to hold tokens.
    pub fn create_token_account(_ctx: Context<CreateTokenAccount>) -> Result<()> {
        Ok(())
    }

    /// Transfer remaining tokens from program owned token account to the "owner" of the state account.
    /// Then close the program owned token account.
    pub fn close_token_account(ctx: Context<CloseTokenAccount>) -> Result<()> {
        let amount = ctx.accounts.program_token_account.amount;
        let decimals = ctx.accounts.mint.decimals;
        let mint_address = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[mint_address.as_ref(), &[ctx.bumps.program_token_account]]];

        // Withdraw all tokens from program owned token account
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            TransferChecked {
                from: ctx.accounts.program_token_account.to_account_info(),
                to: ctx.accounts.destination_token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                authority: ctx.accounts.program_token_account.to_account_info(),
            },
        )
        .with_signer(signer_seeds);
        token_interface::transfer_checked(cpi_ctx, amount, decimals)?;

        // Close the program owned token account (now with 0 balance)
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {  
                account: ctx.accounts.program_token_account.to_account_info(),
                destination: ctx.accounts.owner.to_account_info(),
                authority: ctx.accounts.program_token_account.to_account_info(),
            },
        ).with_signer(signer_seeds);
        token_interface::close_account(cpi_ctx)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    // Use a PDA as the address of the state account.
    #[account(
        init, 
        payer = owner, 
        space = DISCIMINATOR_LEN + State::LEN,
        seeds = [STATE_SEED],
        bump
    )]
    pub state: Account<'info, State>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExpandBitmap<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [STATE_SEED],
        // use the bump seed stored in the state account
        bump = state.bump,
        // check the "owner" field in the state account matches the owner account above
        has_one = owner, 
        // realloc to increase the size (bytes)of the state account
        realloc = state.expand_bitmap_len(),
        // owner account pays for the realloc (SOL)
        realloc::payer = owner,
        realloc::zero = false,
    )]
    pub state: Account<'info, State>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetClaimSigner<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [STATE_SEED],
        bump = state.bump,
        has_one = owner,
    )]
    pub state: Account<'info, State>,
}

#[derive(Accounts)]
pub struct TransferOwnership<'info> {
    #[account(
        mut,
        seeds = [STATE_SEED],
        bump = state.bump,
        has_one = owner,
    )]
    pub state: Account<'info, State>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct UnsetClaimIndex<'info> {
    /// CHECK: We'll rawdog the state.
    #[account(mut)]
    pub state: AccountInfo<'info>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub claimer: Signer<'info>,
    /// CHECK: We'll rawdog the state.
    #[account(
        mut,
        seeds = [STATE_SEED],
        bump
    )]
    pub state: AccountInfo<'info>,

    // InterfaceAccount type allows Mint from both Token Program and Token 2022 Program
    #[account(mut)]
    pub mint: InterfaceAccount<'info, Mint>,

    // InterfaceAccount type allows TokenAccount from both Token Program and Token 2022 Program
    // This is a program owned token account
    #[account(
        mut,    
        seeds = [mint.key().as_ref()],
        bump
    )]
    pub source_token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(
        // create the ATA for claimer if it doesn't exist
        init_if_needed,
        // claimer pays the SOL to create the ATA
        payer = claimer,
        associated_token::mint = mint,
        associated_token::authority = claimer,
        associated_token::token_program = token_program,
    )]
    pub destination_token_account: InterfaceAccount<'info, TokenAccount>,

    // Interface type allows for both Token Program and Token 2022 Program
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: The address check is needed because otherwise
    /// the supplied Sysvar could be anything else.
    /// The Instruction Sysvar has not been implemented
    /// in the Anchor framework yet, so this is the safe approach.
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CreateTokenAccount<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        // create program owned token account if it doesn't exist
        init_if_needed,
        payer = payer,
        // derive the address using the mint address as seed
        seeds = [mint.key().as_ref()],
        bump,
        token::mint = mint,
        // use the PDA as both the address of the token account and the authority (owner)
        // using a PDA as the authority allows the program to "sign" for the token account
        token::authority = program_token_account,
        token::token_program = token_program,

    )]
    pub program_token_account: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseTokenAccount<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        seeds = [STATE_SEED],
        bump = state.bump,
        has_one = owner,
    )]
    pub state: Account<'info, State>,
    #[account(
        mut,
        seeds = [mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = program_token_account,
        token::token_program = token_program,

    )]
    pub program_token_account: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = owner,
        associated_token::mint = mint,
        associated_token::authority = owner,
        associated_token::token_program = token_program,
    )]
    pub destination_token_account: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct State {
    pub bump: u8,                // Bump seed to derive the account PDA, saves on Compute Unit.
    pub owner: Pubkey,           // Program owner's public key.
    pub claim_signer: Pubkey,    // Public key of the claim signer.
    pub claimed_bitmap: Vec<u8>, // Fixed-size bitmap for tracking claimed indices.
}

impl State {
    pub const LEN: usize = INITIAL_STATE_BYTE_LEN;

    pub fn expand_bitmap_len(&self) -> usize {
        BITMAP_BYTES_OFFSET + self.claimed_bitmap.len() + EXTEND_BITMAP_BYTES_LEN
    }
}

#[error_code]
pub enum CustomError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Claim already made")]
    AlreadyClaimed,
    #[msg("Invalid signature")]
    InvalidSignature,
    #[msg("Claim expired")]
    ClaimExpired,
    #[msg("Invalid token program")]
    InvalidTokenProgram,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Invalid destination account")]
    InvalidDestinationAccount,
}

#[event]
pub struct ClaimProcessed {
    pub claimer: Pubkey,
    pub claim_indices: Vec<u32>,
    pub total_amount: u64,
}

#[event]
pub struct OwnershipTransferred {
    pub previous_owner: Pubkey,
    pub new_owner: Pubkey,
}

#[event]
pub struct ClaimSignerUpdated {
    pub previous_claim_signer: Pubkey,
    pub new_claim_signer: Pubkey,
}
