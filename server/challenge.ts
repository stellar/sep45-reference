import {
  authorizeEntry,
  BASE_FEE,
  nativeToScVal,
  SorobanRpc,
  StellarToml,
  TransactionBuilder,
  xdr,
} from "npm:stellar-sdk";
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import jwt from "npm:jsonwebtoken";
import { generateNonce, verifyNonce } from "./nonce.ts";
import xdrParser from "npm:@stellar/js-xdr";
import { createConfig, init } from "./config.ts";
import {
  validateContractAddress,
  validateFunctionName,
  validateAuthEntryStructure,
  validateConsistentArguments,
  validateAuthorizationEntrySignatures,
  validateAuthEntryArguments,
  extractArguments,
  hasClientDomainInArgs,
  validateChallengeRequest,
  validateTokenRequest,
} from "./validation/index.ts";
import type {
  ChallengeRequest,
  ChallengeResponse,
  TokenRequest,
  TokenResponse,
  AuthEntryArgs,
} from "./types.ts";
import { WebAuthError } from "./types.ts";

const config = createConfig();
const {
  network,
  webAuthContract,
  sourceKeypair,
  serverKeypair: sep10SigningKeypair,
  rpc,
} = init(config);

/**
 * Generates a web authentication challenge according to SEP-45
 * 
 * This function creates authorization entries that the client must sign
 * to prove control over their account and complete the authentication flow.
 */
export async function getChallenge(
  request: ChallengeRequest,
): Promise<ChallengeResponse> {
  validateChallengeRequest(request);
  
  const sourceAccount = await rpc.getAccount(sourceKeypair.publicKey());

  // Fetch the signing key from the client domain if provided
  let clientDomainAddress: string | undefined = undefined;
  if (request.client_domain !== undefined) {
    try {
    const clientToml = await StellarToml.Resolver.resolve(request.client_domain);
    clientDomainAddress = clientToml.SIGNING_KEY!;
    } catch (e) {
      throw new Error(
        `Failed to fetch SIGNING_KEY from ${request.client_domain}: ${e}`,
      );
    }
  }

  const nonce = await generateNonce(request.account);

  // Build the `web_auth_verify` invocation arguments
  // NOTE: in js, we can use the `nativeToScVal` helper but we preferred to build the Sc{suffix} objects manually as a reference for other languages.
  const fields = [
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("account"),
      val: nativeToScVal(request.account),
    }),
    ...(request.client_domain !== undefined
      ? [
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("client_domain"),
          val: nativeToScVal(request.client_domain),
        }),
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("client_domain_account"),
          val: nativeToScVal(clientDomainAddress),
        }),
      ]
      : []),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("home_domain"),
      val: nativeToScVal(request.home_domain),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("nonce"),
      val: nativeToScVal(nonce),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("web_auth_domain"),
      val: nativeToScVal(request.home_domain),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("web_auth_domain_account"),
      val: nativeToScVal(sep10SigningKeypair.publicKey()),
    }),
  ];

  const args = [
    xdr.ScVal.scvMap(fields),
  ];
  
  // Build and simulate the transaction to get authorization entries
  const builtTransaction = new TransactionBuilder(sourceAccount, {
    fee: BASE_FEE,
    networkPassphrase: network,
  })
    .addOperation(webAuthContract.call("web_auth_verify", ...args))
    .setTimeout(300)
    .build();

  const simulatedTransaction = await rpc.simulateTransaction(builtTransaction);
  if (SorobanRpc.Api.isSimulationError(simulatedTransaction)) {
    throw new Error(
      `Transaction simulation failed: ${simulatedTransaction.error}`,
    );
  }
  const authEntries = simulatedTransaction.result!.auth;

  // Sign the server's authorization entry
  const finalAuthEntries = authEntries.map(async (entry: xdr.SorobanAuthorizationEntry) => {
    if (
      entry.credentials().switch() ===
        xdr.SorobanCredentialsType.sorobanCredentialsAddress() &&
      entry.credentials().address().address().switch() ===
        xdr.ScAddressType.scAddressTypeAccount()
    ) {
      const validUntilLedgerSeq = (await rpc.getLatestLedger()).sequence + 10;
      const signed = await authorizeEntry(
        entry,
        sep10SigningKeypair,
        validUntilLedgerSeq,
        network,
      );
      return signed;
    }
    return entry;
  });

  const resolvedEntries = await Promise.all(finalAuthEntries);

  const authEntriesType = new xdrParser.VarArray(xdr.SorobanAuthorizationEntry, 10);
  const writer = new xdrParser.XdrWriter();
  authEntriesType.write(resolvedEntries, writer);
  const xdrBuffer = writer.finalize();

  return {
    authorization_entries: xdrBuffer.toString("base64"),
    network_passphrase: network,
  };
}

/**
 * Validates signed authorization entries and issues a JWT token if valid
 */
export async function getToken(
  request: TokenRequest,
): Promise<TokenResponse> {
  validateTokenRequest(request);
  
  let readBuffer: Buffer;
  let authEntries: xdr.SorobanAuthorizationEntry[];
  
  try {
    readBuffer = Buffer.from(request.authorization_entries, "base64");
    if (readBuffer.length === 0) {
      throw new Error("Empty buffer");
    }
  } catch (_error) {
    throw new WebAuthError("Invalid base64 encoding in authorization_entries");
  }
  
  try {
    // Use VarArray to handle dynamic number of authorization entries
    // 2 entries when no client domain (server + client)
    // 3 entries when client domain present (server + client + client domain)
    const authEntriesType = new xdrParser.VarArray(xdr.SorobanAuthorizationEntry, 10);
    const reader = new xdrParser.XdrReader(readBuffer);
    authEntries = authEntriesType.read(reader);
  } catch (_error) {
    throw new WebAuthError("Invalid XDR encoding in authorization_entries");
  }

  validateAuthEntryStructure(authEntries);
  
  // Determine expected entry count based on client domain presence
  const primaryAuthEntry = authEntries[0];
  const hasClientDomain = hasClientDomainInArgs(primaryAuthEntry);
  const expectedEntryCount = hasClientDomain ? 3 : 2;
  
  if (authEntries.length !== expectedEntryCount) {
    throw new WebAuthError(
      `Invalid number of authorization entries. Expected ${expectedEntryCount} ${hasClientDomain ? '(server + client + client domain)' : '(server + client)'}, got ${authEntries.length}`
    );
  }
  
  validateConsistentArguments(authEntries);
  validateContractAddress(primaryAuthEntry, webAuthContract.contractId());
  validateFunctionName(primaryAuthEntry);

  // Extract and validate arguments
  const args: AuthEntryArgs = extractArguments(primaryAuthEntry);
  const {
    account,
    home_domain: homeDomain,
    web_auth_domain: webAuthDomain,
    web_auth_domain_account: _webAuthDomainAccount,
    client_domain: clientDomain,
    client_domain_account: clientDomainAccount,
    nonce,
  } = args;

  validateAuthEntryArguments(
    primaryAuthEntry,
    account,
    homeDomain,
    webAuthDomain,
    sep10SigningKeypair.publicKey(),
    clientDomain,
    clientDomainAccount
  );

  validateAuthorizationEntrySignatures(
    authEntries,
    account,
    sep10SigningKeypair.publicKey(),
    clientDomainAccount
  );

  // Check if the nonce exists and is unused
  if (!(await verifyNonce(account, nonce))) {
    throw new WebAuthError("Invalid or already used nonce");
  }

  // Build transaction for simulation with validated authorization entries
  const contractArgs = primaryAuthEntry.rootInvocation().function().contractFn().args();
  const invokeOp = webAuthContract.call("web_auth_verify", ...contractArgs);
  invokeOp.body().invokeHostFunctionOp().auth(authEntries);

  const sourceAccount = await rpc.getAccount(sep10SigningKeypair.publicKey());
  const builtTransaction = new TransactionBuilder(sourceAccount, {
    fee: BASE_FEE,
    networkPassphrase: network,
  })
    .addOperation(invokeOp)
    .setTimeout(300)
    .build();

  // Simulate the transaction in enforcing mode to verify the credentials
  const simulatedTransaction = await rpc.simulateTransaction(
    builtTransaction,
  );

  if (SorobanRpc.Api.isSimulationError(simulatedTransaction)) {
    throw new WebAuthError(
      `Transaction simulation failed: ${simulatedTransaction.error}`,
    );
  }

  const token = jwt.sign({
    iss: webAuthDomain,
    sub: account,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300,
    jti: createHash("sha256").update(Buffer.from(invokeOp.toXDR().buffer))
      .digest("hex"),
    client_domain: clientDomain,
    home_domain: homeDomain,
  }, config.jwtSecret);

  return { token };
}

// Re-export types and errors for backward compatibility
export { WebAuthError } from "./types.ts";
export type { ChallengeRequest, ChallengeResponse, TokenRequest, TokenResponse } from "./types.ts";