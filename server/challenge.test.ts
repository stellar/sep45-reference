import "https://deno.land/std@0.201.0/dotenv/load.ts";
import { getChallenge, getToken, WebAuthError } from "./challenge.ts";
import { authorizeEntry, Keypair, SorobanRpc, xdr } from "npm:stellar-sdk";
import { Buffer } from "node:buffer";
import { assert, assertRejects } from "jsr:@std/assert";
import xdrParser from "npm:@stellar/js-xdr";

const rpc = new SorobanRpc.Server(Deno.env.get("RPC_URL")!);

async function signAsClient(
  authEntry: xdr.SorobanAuthorizationEntry,
): Promise<xdr.SorobanAuthorizationEntry> {
  const keypair = Keypair.fromSecret(Deno.env.get("WALLET_SIGNER")!);
  const validUntilLedgerSeq = (await rpc.getLatestLedger()).sequence + 10;
  const networkPassphrase = "Test SDF Network ; September 2015";

  return await authorizeEntry(
    authEntry,
    keypair,
    validUntilLedgerSeq,
    networkPassphrase,
  );
}

async function createValidChallenge(clientDomain?: string) {
  const challengeRequest = {
    account: Deno.env.get("WALLET_ADDRESS")!,
    home_domain: "localhost:8080",
    client_domain: clientDomain,
  };

  const challenge = await getChallenge(challengeRequest);
  
  const readBuffer = Buffer.from(challenge.authorization_entries, "base64");
  const authEntriesType = new xdrParser.VarArray(xdr.SorobanAuthorizationEntry, 10);
  const reader = new xdrParser.XdrReader(readBuffer);
  const authorizationEntries: Array<xdr.SorobanAuthorizationEntry> = authEntriesType.read(reader);

  const clientSignedAuthEntry = await signAsClient(authorizationEntries[0]);
  const signedEntries: Array<xdr.SorobanAuthorizationEntry> = [
    clientSignedAuthEntry,
    authorizationEntries[1],
  ];

  const writer = new xdrParser.XdrWriter();
  authEntriesType.write(signedEntries, writer);
  const writeBuffer = writer.finalize();

  return {
    authorizationEntries: signedEntries,
    authorizationEntriesB64: writeBuffer.toString("base64"),
    originalChallenge: challenge,
  };
}

Deno.test("full auth flow without client domain", async () => {
  const challengeRequest = {
    account: Deno.env.get("WALLET_ADDRESS")!,
    memo: "123",
    home_domain: "localhost:8080",
    client_domain: undefined,
  };

  const challenge = await getChallenge(challengeRequest);

  assert(challenge.authorization_entries !== undefined);
  assert(challenge.network_passphrase === "Test SDF Network ; September 2015");

  const readBuffer = Buffer.from(
    challenge.authorization_entries,
    "base64",
  );
  const authEntriesType = new xdrParser.VarArray(xdr.SorobanAuthorizationEntry, 10);
  const reader = new xdrParser.XdrReader(readBuffer);
  const authorizationEntries: Array<xdr.SorobanAuthorizationEntry> =
    authEntriesType
      .read(reader);

  // The client should simulate the transaction with the authorization entries
  // to check that the server signature is valid in addition to making sure that
  // the transaction is not malicious.
  const clientSignedAuthEntry = await signAsClient(
    authorizationEntries[0],
  );

 const signedEntries: Array<xdr.SorobanAuthorizationEntry> = [
    clientSignedAuthEntry,
    authorizationEntries[1],
  ];

  const writer = new xdrParser.XdrWriter();
  authEntriesType.write(signedEntries, writer);
  const writeBuffer = writer.finalize();

  const tokenRequest = {
    authorization_entries: writeBuffer.toString("base64"),
  };

  const token = await getToken(tokenRequest);
  console.log(token);

  assert(token.token !== undefined);
});

Deno.test("getToken fails with invalid base64 characters", async () => {
  const tokenRequest = {
    authorization_entries: "invalid@base64@string",
  };

  await assertRejects(
    () => getToken(tokenRequest),
    WebAuthError,
    "Invalid XDR encoding in authorization_entries"
  );
});

Deno.test("getToken fails with invalid XDR", async () => {
  const tokenRequest = {
    authorization_entries: Buffer.from("invalid xdr data").toString("base64"),
  };

  await assertRejects(
    () => getToken(tokenRequest),
    WebAuthError,
    "Invalid XDR encoding"
  );
});

Deno.test("getToken fails with empty authorization entries", async () => {
  const emptyBuffer = Buffer.alloc(0);

  const tokenRequest = {
    authorization_entries: emptyBuffer.toString("base64"),
  };

  await assertRejects(
    () => getToken(tokenRequest),
    WebAuthError,
    "Missing required parameter: authorization_entries"
  );
});

Deno.test("getToken fails with used nonce", async () => {
  const { authorizationEntriesB64 } = await createValidChallenge();

  const tokenRequest = {
    authorization_entries: authorizationEntriesB64,
  };

  await getToken(tokenRequest);

  await assertRejects(
    () => getToken(tokenRequest),
    WebAuthError,
    "Invalid or already used nonce"
  );
});

Deno.test("getChallenge fails with missing account parameter", async () => {
  await assertRejects(
    () => getChallenge({
      account: "",
      home_domain: "localhost:8080",
      client_domain: undefined,
    }),
    WebAuthError,
    "Missing required parameter: account"
  );
});

Deno.test("getChallenge fails with missing home_domain parameter", async () => {
  await assertRejects(
    () => getChallenge({
      account: Deno.env.get("WALLET_ADDRESS")!,
      home_domain: "",
      client_domain: undefined,
    }),
    WebAuthError,
    "Missing required parameter: home_domain"
  );
});

Deno.test("getChallenge fails with invalid client_domain", async () => {
  await assertRejects(
    () => getChallenge({
      account: Deno.env.get("WALLET_ADDRESS")!,
      home_domain: "localhost:8080",
      client_domain: "nonexistent-domain-that-will-fail.invalid",
    }),
    Error,
    "Failed to fetch SIGNING_KEY"
  );
});

Deno.test("getChallenge with client domain does not include client arguments", async () => {
  const challengeRequest = {
    account: Deno.env.get("WALLET_ADDRESS")!,
    home_domain: "localhost:8080",
    client_domain: undefined,
  };

  const challenge = await getChallenge(challengeRequest);
  
  const readBuffer = Buffer.from(challenge.authorization_entries, "base64");
  const authEntriesType = new xdrParser.VarArray(xdr.SorobanAuthorizationEntry, 10);
  const reader = new xdrParser.XdrReader(readBuffer);
  const authorizationEntries = authEntriesType.read(reader);
  
  const args = authorizationEntries[0].rootInvocation().function().contractFn().args();
  const argEntries = args[0].map()!;
  
  let hasClientDomain = false;
  let hasClientDomainAccount = false;
  
  for (const entry of argEntries) {
    const key = entry.key().sym().toString();
    if (key === "client_domain") hasClientDomain = true;
    if (key === "client_domain_account") hasClientDomainAccount = true;
  }
  
  assert(!hasClientDomain, "Should not have client_domain when not provided");
  assert(!hasClientDomainAccount, "Should not have client_domain_account when not provided");
});

Deno.test("getChallenge network passphrase consistency", async () => {
  const challengeRequest = {
    account: Deno.env.get("WALLET_ADDRESS")!,
    home_domain: "localhost:8080",
    client_domain: undefined,
  };

  const challenge = await getChallenge(challengeRequest);
  
  assert(challenge.network_passphrase === "Test SDF Network ; September 2015");
});

Deno.test("getToken fails with inconsistent arguments across authorization entries", async () => {
  // TODO
});


Deno.test("getToken fails with empty authorization array", async () => {
  const authEntriesType = new xdrParser.VarArray(xdr.SorobanAuthorizationEntry, 10);
  const writer = new xdrParser.XdrWriter();
  authEntriesType.write([], writer);
  const writeBuffer = writer.finalize();

  const tokenRequest = {
    authorization_entries: writeBuffer.toString("base64"),
  };

  await assertRejects(
    () => getToken(tokenRequest),
    WebAuthError,
    "No authorization entries provided"
  );
});

Deno.test("getToken fails with wrong number of authorization entries", async () => {
  const { authorizationEntries } = await createValidChallenge();
  
  const invalidEntries = [authorizationEntries[0]];
  
  const authEntriesType = new xdrParser.VarArray(xdr.SorobanAuthorizationEntry, 10);
  const writer = new xdrParser.XdrWriter();
  authEntriesType.write(invalidEntries, writer);
  const writeBuffer = writer.finalize();

  const tokenRequest = {
    authorization_entries: writeBuffer.toString("base64"),
  };

  await assertRejects(
    () => getToken(tokenRequest),
    WebAuthError,
    "Invalid number of authorization entries. Expected 2"
  );
});
