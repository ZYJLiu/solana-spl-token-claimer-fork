import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { TokenClaimer } from "../target/types/token_claimer";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  SystemProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import * as splToken from "@solana/spl-token";
import * as fs from "fs";
import * as nacl from "tweetnacl";

const loadKeypair = (path) => {
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(path, "utf-8")))
  );
};

const savePublicKey = (path, publicKey) => {
  fs.writeFileSync(path, JSON.stringify(Array.from(publicKey.toBytes())));
};

const loadPublicKey = (path) => {
  return new PublicKey(Uint8Array.from(JSON.parse(fs.readFileSync(path, "utf-8"))));
};

(async () => {  
  // Set up the provider
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const connection = provider.connection;

  const program = anchor.workspace.TokenClaimer as Program<TokenClaimer>;

  // Load keypairs
  const stateAccount = loadKeypair("keypairs/state_account.json");
  const mintAuthority = loadKeypair("keypairs/mint_keypair.json");
  const deployer = loadKeypair("keypairs/deployer.json");
  const claimSigner = loadKeypair("keypairs/claim_signer.json");
  const splTokenMint = loadPublicKey("keypairs/spl_token.json");
  const sourceTokenAccount = loadPublicKey("keypairs/spl_token_for_deployer.json");
  const claimer = loadKeypair("keypairs/claimer.json");
  const destination = loadKeypair("keypairs/destination.json");

  let state = await program.account.state.fetch(stateAccount.publicKey);
 
  console.log("State Accoount:", stateAccount.publicKey.toBase58());
  console.log("Mint Authority:", mintAuthority.publicKey.toBase58());
  console.log("Deployer:", deployer.publicKey.toBase58());
  console.log("Claim Signer:", claimSigner.publicKey.toBase58());
  console.log("SPL Token Mint:", splTokenMint.toBase58());
  console.log("Source Token Account:", sourceTokenAccount.toBase58());
  console.log("Claimer:", claimer.publicKey.toBase58());
  console.log("Destination:", destination.publicKey.toBase58());
  
  try {
    console.log("Deployer balance:", await connection.getBalance(deployer.publicKey));
    console.log("Source token balance:", (await splToken.getAccount(connection, sourceTokenAccount)).amount);
  } catch (err) {
    console.error(err);
  }

  const expectedDestinationTokenAccount = await splToken.getAssociatedTokenAddress(
    splTokenMint, 
    destination.publicKey
  );
  console.log("Expected Destination Token Account:", expectedDestinationTokenAccount.toBase58());

  const claimIndex = new anchor.BN(100);
  const amount = new anchor.BN(123);

  const message = Buffer.concat([
    claimIndex.toArrayLike(Buffer, "be", 4),
    sourceTokenAccount.toBuffer(),
    expectedDestinationTokenAccount.toBuffer(), 
    amount.toArrayLike(Buffer, "be", 8),
  ]);
  console.log("Message:", message.length, message.toString("hex"));
  const signature = nacl.sign.detached(message, claimSigner.secretKey);
  console.log("Signature:", Buffer.from(signature).toString("hex"));

  console.log("Program Owner:", state.owner.toBase58());
  console.log("Program Claim Signer:", state.claimSigner.toBase58());

  try {
    const ed25519InstructionIndex = new anchor.BN(0);
    const tx = await program.methods
      .claim(ed25519InstructionIndex, claimIndex, amount, signature)
      .accounts({
        state: stateAccount.publicKey,
        claimer: claimer.publicKey,
        sourceTokenAccount: sourceTokenAccount,
        destinationTokenAccount: expectedDestinationTokenAccount,
        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .preInstructions([
        anchor.web3.Ed25519Program.createInstructionWithPublicKey({
          publicKey: claimSigner.publicKey.toBytes(),
          message: message,
          signature: signature,
        }),
        splToken.createAssociatedTokenAccountIdempotentInstruction(
          claimer.publicKey,
          expectedDestinationTokenAccount,
          destination.publicKey, 
          splTokenMint 
        ),
      ])
      .signers([claimer])
      .rpc();
  } catch (err) {
    console.error(err);
    if (err.transactionLogs) {
      console.error("Transaction logs:", err.transactionLogs);
    }
    throw err;
  }
})();
