use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use solana_program::keccak::Hasher;
use solana_program::secp256k1_recover::secp256k1_recover;

declare_id!("BT9KtHpp84B2AJmLHg3cBAnqP2cc8cNjQ8UV4kL3NEcQ");

const OWNER_OFFSET: usize = 8; // Skip discriminator (8 bytes).
const CLAIM_SIGNER_OFFSET: usize = OWNER_OFFSET + 32; // Skip 32 bytes.
const BITMAP_LEN_OFFSET: usize = CLAIM_SIGNER_OFFSET + 20; // Skip claim signer.
const INITIAL_STATE_BYTE_LEN: usize = BITMAP_LEN_OFFSET + 128;

#[program]
pub mod token_claimer {
    use super::*;

    /// Initialize the program state.
    pub fn initialize(ctx: Context<Initialize>, claim_signer: [u8; 20]) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.owner = ctx.accounts.owner.key();
        state.claim_signer = claim_signer;
        state.claimed_bitmap = Vec::new();
        Ok(())
    }

    /// Expands the bitmap by 10_000 bytes (80_000 bits).
    pub fn expand_bitmap(ctx: Context<ExpandBitmap>) -> Result<()> {
        let state_info = &ctx.accounts.state;

        // Check if the caller is the owner
        require!(
            ctx.accounts.owner.key()
                == Pubkey::new_from_array(
                    state_info.data.borrow()[OWNER_OFFSET..OWNER_OFFSET + 32]
                        .try_into()
                        .unwrap()
                ),
            CustomError::Unauthorized
        );

        let current_bitmap_len = u32::from_le_bytes(
            state_info.data.borrow()[BITMAP_LEN_OFFSET..BITMAP_LEN_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let new_bitmap_len = current_bitmap_len + 10_000;
        require!(
            new_bitmap_len >= current_bitmap_len,
            CustomError::ExpandBitmapOverflow
        );
        let new_account_size = BITMAP_LEN_OFFSET + 4 + new_bitmap_len as usize;

        if new_account_size > state_info.data_len() {
            state_info.realloc(new_account_size, false)?;
        }

        state_info.data.borrow_mut()[BITMAP_LEN_OFFSET..BITMAP_LEN_OFFSET + 4]
            .copy_from_slice(&(new_bitmap_len as u32).to_le_bytes());

        Ok(())
    }

    /// Update the claim signer (only callable by the program owner).
    pub fn set_claim_signer(
        ctx: Context<SetClaimSigner>,
        new_claim_signer: [u8; 20],
    ) -> Result<()> {
        // Owner check.
        require!(
            ctx.accounts.owner.key() == ctx.accounts.state.owner,
            CustomError::Unauthorized
        );
        // Update the state.
        let previous_claim_signer = ctx.accounts.state.claim_signer;
        ctx.accounts.state.claim_signer = new_claim_signer;
        // Emit the event.
        emit!(ClaimSignerUpdated {
            previous_claim_signer: previous_claim_signer,
            new_claim_signer: new_claim_signer,
        });
        Ok(())
    }

    /// Transfer ownership of the program.
    pub fn transfer_ownership(ctx: Context<TransferOwnership>, new_owner: Pubkey) -> Result<()> {
        // Owner check.
        require!(
            ctx.accounts.owner.key() == ctx.accounts.state.owner,
            CustomError::Unauthorized
        );
        // Update the state.
        let previous_owner = ctx.accounts.state.owner;
        ctx.accounts.state.owner = new_owner;
        // Emit the event.
        emit!(OwnershipTransferred {
            previous_owner: previous_owner,
            new_owner,
        });
        Ok(())
    }

    /// Process a claim for tokens with a valid signature.
    pub fn claim(
        ctx: Context<Claim>,
        claim_index: u64,
        amount: u64,
        signature: Vec<u8>,
    ) -> Result<()> {
        // Check if the claim index has already been processed.
        let byte_index = (claim_index >> 3) as usize; // Division by 8 (bit shift).
        let bit_index = (claim_index & 7) as u8; // Modulo 8 (bit mask).
        require!(
            byte_index < ctx.accounts.state.claimed_bitmap.len(),
            CustomError::InvalidClaimIndex
        );
        let bit_mask = 1 << bit_index;
        require!(
            ctx.accounts.state.claimed_bitmap[byte_index] & bit_mask == 0,
            CustomError::AlreadyClaimed
        );

        // Construct the message for hashing.
        let mut message = Vec::with_capacity(80);
        message.extend_from_slice(&claim_index.to_be_bytes());
        message.extend_from_slice(&ctx.accounts.claimer.key().to_bytes());
        message.extend_from_slice(&ctx.accounts.source_token_account.key().to_bytes());
        message.extend_from_slice(&amount.to_be_bytes());

        // Hash the message using Keccak-256.
        let mut hasher = Hasher::default();
        hasher.hash(&message);
        let message_hash = hasher.result();

        // Recover the public key from the signature.
        let mut rs = [0u8; 64];
        let mut v = 0u8;
        if signature.len() == 65 {
            rs.copy_from_slice(&signature[..64]);
            v = signature[64];
            require!(v == 27 || v == 28, CustomError::InvalidSignature);
            v -= 27;
        } else if signature.len() == 64 {
            rs.copy_from_slice(&signature);
            v = signature[32] >> 7; // Extract highest bit of `s` as `v`.
            rs[32] &= 0x7F; // Clear the highest bit.
        } else {
            require!(false, CustomError::InvalidSignature)
        }
        let recovered_pubkey = secp256k1_recover(&message_hash.to_bytes(), v, &rs)
            .map_err(|_| CustomError::InvalidSignature)?;

        // Compute the bytes20 of the recovered public key.
        let mut hasher = Hasher::default();
        hasher.hash(&recovered_pubkey.to_bytes());

        // Compare with the stored claim signer.
        require!(
            hasher.result().to_bytes()[12..] == ctx.accounts.state.claim_signer,
            CustomError::InvalidSignature
        );

        // Mark the claim as processed.
        ctx.accounts.state.claimed_bitmap[byte_index] |= bit_mask;

        // Transfer the tokens.
        // Note: we don't check that `destination_token_account` is owned by `claimer`,
        // to allow the flexibility of transferring to a destination of `claimer's` choice.
        // Ensure there are enough tokens in the source account.
        require!(
            ctx.accounts.source_token_account.amount >= amount,
            CustomError::InsufficientFunds
        );
        // Ensure the token program is correct.
        require!(
            ctx.accounts.token_program.key() == anchor_spl::token::ID,
            CustomError::InvalidTokenProgram
        );
        // Perform the token transfer.
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.source_token_account.to_account_info(),
                to: ctx.accounts.destination_token_account.to_account_info(),
                authority: ctx.accounts.state.to_account_info(), // Program-owned authority
            },
        );
        token::transfer(cpi_ctx, amount)?;

        // Emit the claim event.
        emit!(ClaimProcessed {
            claimer: ctx.accounts.claimer.key(),
            claim_index,
            amount,
        });

        Ok(())
    }

    /// Withdraw SPL tokens from the program's token account (only callable by the owner).
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // Owner check.
        require!(
            ctx.accounts.owner.key() == ctx.accounts.state.owner,
            CustomError::Unauthorized
        );
        // Ensure there are enough tokens in the source account.
        require!(
            ctx.accounts.source_token_account.amount >= amount,
            CustomError::InsufficientFunds
        );
        // Ensure the token program is correct.
        require!(
            ctx.accounts.token_program.key() == anchor_spl::token::ID,
            CustomError::InvalidTokenProgram
        );
        // Perform the token transfer.
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.source_token_account.to_account_info(),
                to: ctx.accounts.destination_token_account.to_account_info(),
                authority: ctx.accounts.state.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, amount)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = owner, space = 8 + State::LEN)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub owner: Signer<'info>, // `msg.sender`.
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExpandBitmap<'info> {
    #[account(mut)]
    /// CHECK: make sure state is properly resized.
    pub state: AccountInfo<'info>,
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetClaimSigner<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub owner: Signer<'info>, // `msg.sender`.
}

#[derive(Accounts)]
pub struct TransferOwnership<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub owner: Signer<'info>, // `msg.sender`.
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub source_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination_token_account: Account<'info, TokenAccount>,
    pub claimer: Signer<'info>, // `msg.sender`.
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub state: Account<'info, State>, // The program state account
    #[account(mut)]
    pub source_token_account: Account<'info, TokenAccount>, // Program-owned token account
    #[account(mut)]
    pub destination_token_account: Account<'info, TokenAccount>, // Owner's token account
    pub owner: Signer<'info>, // Program owner
    pub token_program: Program<'info, Token>, // SPL token program
}

#[account]
pub struct State {
    pub owner: Pubkey,           // Program owner's public key.
    pub claim_signer: [u8; 20],  // Lower 20 bytes of the keccak256 hash of the public key.
    pub claimed_bitmap: Vec<u8>, // Fixed-size bitmap for tracking claimed indices.
}

impl State {
    pub const LEN: usize = INITIAL_STATE_BYTE_LEN;
}

#[error_code]
pub enum CustomError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Invalid claim index")]
    InvalidClaimIndex,
    #[msg("Claim already made")]
    AlreadyClaimed,
    #[msg("Invalid signature")]
    InvalidSignature,
    #[msg("Invalid token program")]
    InvalidTokenProgram,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Invalid destination account")]
    InvalidDestinationAccount,
    #[msg("Expand bitmap overflow")]
    ExpandBitmapOverflow,
}

#[event]
pub struct ClaimProcessed {
    pub claimer: Pubkey,
    pub claim_index: u64,
    pub amount: u64,
}

#[event]
pub struct OwnershipTransferred {
    pub previous_owner: Pubkey,
    pub new_owner: Pubkey,
}

#[event]
pub struct ClaimSignerUpdated {
    pub previous_claim_signer: [u8; 20],
    pub new_claim_signer: [u8; 20],
}
