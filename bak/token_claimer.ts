import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TokenClaimer } from "../target/types/token_claimer";
import { PublicKey, SystemProgram, Keypair } from "@solana/web3.js";
import { Token, TOKEN_PROGRAM_ID, createMint, createAccount, createAssociatedTokenAccount,getAssociatedTokenAddress, mintTo, getAccount } from "@solana/spl-token";
import { assert, expect } from "chai";

describe("token_claimer", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());
  const provider = anchor.AnchorProvider.env();
  const program = anchor.workspace.TokenClaimer as Program<TokenClaimer>;

  // Test accounts
  let owner = Keypair.generate();
  let newOwner = Keypair.generate();
  let claimer = Keypair.generate();
  let destination = Keypair.generate();
  let stateAccount = Keypair.generate();
  let mint: PublicKey;
  let sourceTokenAccount: PublicKey;
  let destinationTokenAccount: PublicKey;

  const stripHexPrefix = s => s.replace(/^0[xX]/, '');

  async function getSplTokenBalance(
    connection: Connection,
    owner: PublicKey, // The public key of the owner
    mint: PublicKey   // The mint address of the SPL token
  ): Promise<number> {
    // Derive the associated token address for the owner and mint
    const tokenAccountAddress = await getAssociatedTokenAddress(mint, owner);
  
    try {
      // Fetch the token account information
      const tokenAccountInfo = await getAccount(connection, tokenAccountAddress);
  
      // Return the balance (amount is in raw token units, not adjusted for decimals)
      return Number(tokenAccountInfo.amount);
    } catch (err) {
      // If the account does not exist, return a balance of 0
      if (err.message.includes("Failed to find account")) {
        return 0;
      } else {
        throw err;
      }
    }
  }

  it("Initializes the program state", async () => {
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(owner.publicKey, 111 * anchor.web3.LAMPORTS_PER_SOL)
    );
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(newOwner.publicKey, 111 * anchor.web3.LAMPORTS_PER_SOL)
    );
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(claimer.publicKey, 111 * anchor.web3.LAMPORTS_PER_SOL)
    );

    const claimSigner = stripHexPrefix("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    await program.methods
      .initialize(anchor.utils.bytes.hex.decode(claimSigner))
      .accounts({
        state: stateAccount.publicKey,
        owner: owner.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner, stateAccount])
      .rpc();

    let state = await program.account.state.fetch(stateAccount.publicKey);

    expect(state.owner.toBase58()).to.equal(owner.publicKey.toBase58());
    expect(stripHexPrefix(anchor.utils.bytes.hex.encode(state.claimSigner)), '')
      .to.deep.equal(claimSigner);
    
    await provider.connection.confirmTransaction(
      await provider.connection.requestAirdrop(stateAccount.publicKey, 111 * anchor.web3.LAMPORTS_PER_SOL)
    );

    await program.methods
      .expandBitmap()
      .accounts({
        state: stateAccount.publicKey,
        owner: owner.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();
    
    await program.methods
      .expandBitmap()
      .accounts({
        state: stateAccount.publicKey,
        owner: owner.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();
      
    state = await program.account.state.fetch(stateAccount.publicKey);
    expect(state.claimedBitmap.length).to.eq(20000);

    expect(stripHexPrefix(anchor.utils.bytes.hex.encode(state.claimSigner)), '')
      .to.deep.equal(claimSigner);
  });

  it("Updates the claim signer", async () => {
    const newClaimSigner = stripHexPrefix("cafebabecafebabecafebabecafebabecafebabe");

    await program.methods
      .setClaimSigner(anchor.utils.bytes.hex.decode(newClaimSigner))
      .accounts({
        state: stateAccount.publicKey,
        owner: owner.publicKey,
      })
      .signers([owner])
      .rpc();

    const state = await program.account.state.fetch(stateAccount.publicKey);
    expect(stripHexPrefix(anchor.utils.bytes.hex.encode(state.claimSigner)), '')
      .to.deep.equal(newClaimSigner);
  });

  it("Transfers ownership", async () => {
    await program.methods
      .transferOwnership(newOwner.publicKey)
      .accounts({
        state: stateAccount.publicKey,
        owner: owner.publicKey,
      })
      .signers([owner])
      .rpc();

    const state = await program.account.state.fetch(stateAccount.publicKey);
    expect(state.owner.toBase58()).to.equal(newOwner.publicKey.toBase58());

    await program.methods
      .transferOwnership(owner.publicKey)
      .accounts({
        state: stateAccount.publicKey,
        owner: newOwner.publicKey,
      })
      .signers([newOwner])
      .rpc();
  });

  it("Can withdraw tokens", async () => {
    // Create a token mint
    mint = await createMint(provider.connection, owner, owner.publicKey, null, 9);

    // Create token accounts
    sourceTokenAccount = await createAssociatedTokenAccount(
      provider.connection,
      owner,
      mint,
      stateAccount.publicKey
    );

    destinationTokenAccount = await createAssociatedTokenAccount(
      provider.connection,
      owner,
      mint,
      destination.publicKey
    );
    // Fetch the source token account details
    const sourceAccountInfo = await getAccount(provider.connection, sourceTokenAccount);

    // Fetch the destination token account details
    const destinationAccountInfo = await getAccount(provider.connection, destinationTokenAccount);

    // Print the owner of each token account
    console.log("Source Token Account Owner:", sourceAccountInfo.owner.toString());
    console.log("Destination Token Account Owner:", destinationAccountInfo.owner.toString());
    console.log("S:", stateAccount.publicKey.toString());
    console.log("D:", destination.publicKey.toString());

    console.log("Source Token Account Aalance:", 
      await getSplTokenBalance(provider.connection, stateAccount.publicKey, mint)
    );
    
    // Mint tokens to the source account
    await mintTo(
      provider.connection,
      owner,
      mint,
      sourceTokenAccount,
      owner.publicKey,
      1000 * 10 ** 9 // Mint 1000 tokens
    );

    console.log("Source Token Account Aalance:", 
      await getSplTokenBalance(provider.connection, stateAccount.publicKey, mint)
    );

    // Convert the amount to a BN instance
    const amount = new anchor.BN(1000).mul(new anchor.BN(10).pow(new anchor.BN(9))); // 1000 * 10^9

    await program.methods
      .withdraw(amount)
      .accounts({
        state: stateAccount.publicKey,
        owner: owner.publicKey,
        sourceTokenAccount: sourceTokenAccount,
        destinationTokenAccount: destinationTokenAccount,
      })
      .signers([owner])
      .rpc();
  });

  // it("Processes a valid claim", async () => {
  //   const claimIndex = new anchor.BN(1);
  //   const amount = new anchor.BN(100 * 10 ** 9); // Claim 100 tokens

  //   // Generate a mock signature for the claim
  //   const message = Buffer.concat([
  //     claimIndex.toArrayLike(Buffer, "be", 8),
  //     claimer.publicKey.toBuffer(),
  //     sourceTokenAccount.toBuffer(),
  //     amount.toArrayLike(Buffer, "be", 8),
  //   ]);
  //   const messageHash = anchor.web3.keccak256(message);

  //   // Generate a dummy signature (replace with secp256k1 signature if needed)
  //   const signature = Buffer.concat([messageHash, Buffer.from([27])]);

  //   await program.methods
  //     .claim(claimIndex, amount, Array.from(signature))
  //     .accounts({
  //       state: stateAccount.publicKey,
  //       sourceTokenAccount: sourceTokenAccount,
  //       destinationTokenAccount: destinationTokenAccount,
  //       claimer: claimer.publicKey,
  //       tokenProgram: anchor.utils.token.TOKEN_PROGRAM_ID,
  //     })
  //     .signers([claimer])
  //     .rpc();

  //   const state = await program.account.state.fetch(stateAccount.publicKey);
  //   const claimedBitmap = state.claimedBitmap;

  //   // Verify the claim index was marked as claimed
  //   const byteIndex = Math.floor(claimIndex.toNumber() / 8);
  //   const bitIndex = claimIndex.toNumber() % 8;
  //   const bitMask = 1 << bitIndex;

  //   expect((claimedBitmap[byteIndex] & bitMask) !== 0).to.be.true;

  //   const destinationAccount = await token.getAccount(provider.connection, destinationTokenAccount);
  //   expect(destinationAccount.amount).to.equal(amount.toNumber());
  // });
});
