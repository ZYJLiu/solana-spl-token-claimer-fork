import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TokenClaimer } from "../target/types/token_claimer";
import {
  PublicKey,
  Keypair,
  TransactionMessage,
  VersionedMessage,
  VersionedTransaction,
  Transaction,
  Connection,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  createMint,
  getAssociatedTokenAddress,
  mintTo,
  getAccount,
  TOKEN_2022_PROGRAM_ID,
} from "@solana/spl-token";
import { expect } from "chai";
import * as nacl from "tweetnacl";
import { keccak_256 } from "@noble/hashes/sha3";

describe("token_claimer", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());
  const provider = anchor.AnchorProvider.env();
  const program = anchor.workspace.TokenClaimer as Program<TokenClaimer>;
  const wallet = provider.wallet as anchor.Wallet;

  // Test accounts
  let owner = wallet.payer;
  let newOwner = Keypair.generate();
  // address claiming tokens
  let claimer = Keypair.generate();
  // an admin address to sign for approving the amount of tokens that can be claimed by a "claimer"
  let claimSigner = Keypair.generate();
  let mint = Keypair.generate();

  // PDA for the state account
  let [stateAccount] = PublicKey.findProgramAddressSync(
    [Buffer.from("state")],
    program.programId
  );

  // PDA for the program owned token account
  let [programTokenAccount] = PublicKey.findProgramAddressSync(
    [mint.publicKey.toBuffer()],
    program.programId
  );

  before(async () => {
    // Create a token mint
    await createMint(
      provider.connection,
      owner,
      owner.publicKey,
      null,
      2,
      mint,
      {
        commitment: "confirmed",
      },
      TOKEN_2022_PROGRAM_ID
    );

    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(
        owner.publicKey,
        111 * anchor.web3.LAMPORTS_PER_SOL
      )
    );
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(
        newOwner.publicKey,
        111 * anchor.web3.LAMPORTS_PER_SOL
      )
    );
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(
        claimer.publicKey,
        111 * anchor.web3.LAMPORTS_PER_SOL
      )
    );
  });

  it("Initializes the program state", async () => {
    // Anchor can infer the accounts required using the IDL
    await program.methods.initialize(claimSigner.publicKey).rpc();

    let state = await program.account.state.fetch(stateAccount);

    expect(state.owner.toBase58()).to.equal(owner.publicKey.toBase58());
    expect(state.claimSigner).to.deep.equal(claimSigner.publicKey);
  });

  it("Realloc the program state", async () => {
    for (let i = 0; i < 8; i++) {
      // Anchor can infer the accounts required using the IDL
      await program.methods.expandBitmap().rpc();
    }

    let state = await program.account.state.fetch(stateAccount);
    expect(state.claimedBitmap.length).to.eq(8000);
    expect(state.claimSigner).to.deep.equal(claimSigner.publicKey);
    expect(state.owner).to.deep.equal(owner.publicKey);
  });

  it("Updates the claim signer", async () => {
    const newClaimSigner = Keypair.generate();
    // Update the "claim signer"
    await program.methods.setClaimSigner(newClaimSigner.publicKey).rpc();

    const state = await program.account.state.fetch(stateAccount);
    expect(state.claimSigner).to.deep.equal(newClaimSigner.publicKey);

    // Reset the "claim signer" back to the original
    await program.methods.setClaimSigner(claimSigner.publicKey).rpc();
  });

  it("Transfers ownership", async () => {
    // Update "owner" field in the state account
    await program.methods.transferOwnership(newOwner.publicKey).rpc();

    const state = await program.account.state.fetch(stateAccount);
    expect(state.owner.toBase58()).to.equal(newOwner.publicKey.toBase58());

    // Reset the "owner" field back to the original
    await program.methods
      .transferOwnership(owner.publicKey)
      .accounts({
        owner: newOwner.publicKey,
      })
      .signers([newOwner])
      .rpc();
  });

  it("Create Program Token Account", async () => {
    await program.methods
      .createTokenAccount()
      .accounts({
        mint: mint.publicKey,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
      })
      .rpc({ commitment: "confirmed" });

    // 100 tokens
    const amount = 100 * 10 ** 2;
    // Fund the program token account
    await mintTo(
      provider.connection,
      owner,
      mint.publicKey,
      programTokenAccount,
      owner.publicKey,
      amount,
      [],
      { commitment: "confirmed" },
      TOKEN_2022_PROGRAM_ID
    );

    // fetch the program token account
    const tokenAccount = await getAccount(
      provider.connection,
      programTokenAccount,
      "confirmed",
      TOKEN_2022_PROGRAM_ID
    );

    expect(tokenAccount.amount).to.equal(BigInt(amount));
    expect(tokenAccount.mint.toBase58()).to.equal(mint.publicKey.toBase58());
    // Using same PDA as both address of the token account and the owner
    expect(tokenAccount.owner.toBase58()).to.equal(
      programTokenAccount.toBase58()
    );
  });

  it("Can claim tokens", async () => {
    // ATA for the claimer
    const expectedDestinationTokenAccount = await getAssociatedTokenAddress(
      mint.publicKey,
      claimer.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID
    );

    // Claims to be made (20) = 0.2 tokens
    const claims = [
      { claimIndex: 30110, amount: 1 },
      { claimIndex: 30111, amount: 1 },
      { claimIndex: 30112, amount: 1 },
      { claimIndex: 30113, amount: 1 },
      { claimIndex: 30114, amount: 1 },
      { claimIndex: 30115, amount: 1 },
      { claimIndex: 30116, amount: 1 },
      { claimIndex: 30117, amount: 1 },
      { claimIndex: 30118, amount: 1 },
      { claimIndex: 30119, amount: 1 },
      { claimIndex: 30120, amount: 1 },
      { claimIndex: 30121, amount: 1 },
      { claimIndex: 30122, amount: 1 },
      { claimIndex: 30123, amount: 1 },
      { claimIndex: 30124, amount: 1 },
      { claimIndex: 30125, amount: 1 },
      { claimIndex: 30126, amount: 1 },
      { claimIndex: 30127, amount: 1 },
      { claimIndex: 30128, amount: 1 },
      { claimIndex: 30129, amount: 1 },
    ];

    let instructions = [];
    let claimIndices = [];
    let totalAmount = 0;
    for (let i = 0; i < claims.length; i++) {
      const { claimIndex, amount } = claims[i];
      totalAmount += amount;
      claimIndices.push(claimIndex);
    }

    const slot = await provider.connection.getSlot({ commitment: "confirmed" });
    const timestamp = await provider.connection.getBlockTime(slot);
    const expiry = timestamp + 60;

    // Message to sign by "claim signer", with parameters of the claim
    const message = keccak_256(
      Buffer.concat([
        keccak_256(
          Buffer.concat(
            claimIndices.map((i) =>
              new anchor.BN(i).toArrayLike(Buffer, "le", 4)
            )
          )
        ),
        claimer.publicKey.toBuffer(),
        programTokenAccount.toBuffer(),
        expectedDestinationTokenAccount.toBuffer(),
        new anchor.BN(totalAmount).toArrayLike(Buffer, "le", 8),
        new anchor.BN(expiry).toArrayLike(Buffer, "le", 4),
      ])
    );
    const signature = nacl.sign.detached(message, claimSigner.secretKey);

    instructions.push(
      // Instruction with signed message to verify in the program instruction
      anchor.web3.Ed25519Program.createInstructionWithPublicKey({
        publicKey: claimSigner.publicKey.toBytes(),
        message: message,
        signature: signature,
      }),
      // Instruction to claim the tokens
      await program.methods
        .claim(claimIndices, new anchor.BN(totalAmount), expiry)
        .accounts({
          claimer: claimer.publicKey,
          mint: mint.publicKey,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
        })
        .instruction()
    );

    const transaction = new Transaction().add(...instructions);
    transaction.feePayer = claimer.publicKey;

    await sendAndConfirmTransaction(
      provider.connection,
      transaction,
      [claimer],
      { commitment: "confirmed" }
    );

    // fetch the program token account
    const sourceTokenAccount = await getAccount(
      provider.connection,
      programTokenAccount,
      "confirmed",
      TOKEN_2022_PROGRAM_ID
    );

    // fetch the claimer's token account
    const destinationTokenAccount = await getAccount(
      provider.connection,
      expectedDestinationTokenAccount,
      "confirmed",
      TOKEN_2022_PROGRAM_ID
    );
    console.log("Source Token Balance:", sourceTokenAccount.amount);
    console.log("Destination Token Balance:", destinationTokenAccount.amount);
  });

  it("Close Program Token Account", async () => {
    // Withdrawn all tokens from the program token account and close it
    await program.methods
      .closeTokenAccount()
      .accounts({
        mint: mint.publicKey,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
      })
      .rpc();
  });
});
