import { xdr, scValToNative } from "npm:stellar-sdk";
import { WebAuthError, AuthEntryArgs } from "../types.ts";

/**
 * Extracts arguments from an authorization entry into a typed interface
 */
export function extractArguments(authEntry: xdr.SorobanAuthorizationEntry): AuthEntryArgs {
  const args = authEntry.rootInvocation().function().contractFn().args();
  
  if (args.length !== 1 || args[0].switch() !== xdr.ScValType.scvMap()) {
    throw new WebAuthError("Invalid authorization entry arguments structure");
  }
  
  const argEntries = args[0].map()!;
  const argsMap = new Map<string, string>();
  
  for (const entry of argEntries) {
    const key = entry.key().sym().toString();
    const value = scValToNative(entry.val());
    argsMap.set(key, value);
  }
  
  const account = argsMap.get("account");
  const home_domain = argsMap.get("home_domain");
  const web_auth_domain = argsMap.get("web_auth_domain");
  const web_auth_domain_account = argsMap.get("web_auth_domain_account");
  const nonce = argsMap.get("nonce");
  
  if (!account || !home_domain || !web_auth_domain || !web_auth_domain_account || !nonce) {
    throw new WebAuthError("Missing required arguments in authorization entry");
  }
  
  return {
    account,
    home_domain,
    web_auth_domain,
    web_auth_domain_account,
    nonce,
    client_domain: argsMap.get("client_domain"),
    client_domain_account: argsMap.get("client_domain_account"),
  };
}

/**
 * Validates authorization entry arguments against expected values
 */
export function validateAuthEntryArguments(
  authEntry: xdr.SorobanAuthorizationEntry,
  expectedAccount: string,
  expectedHomeDomain: string,
  expectedWebAuthDomain: string,
  expectedWebAuthDomainAccount: string,
  expectedClientDomain?: string,
  expectedClientDomainAccount?: string
): void {
  const args = authEntry.rootInvocation().function().contractFn().args();
  if (args.length !== 1 || args[0].switch() !== xdr.ScValType.scvMap()) {
    throw new WebAuthError("Invalid authorization entry arguments structure");
  }
  
  const argEntries = args[0].map()!;
  const argsMap = new Map<string, string>();
  
  for (const entry of argEntries) {
    const key = entry.key().sym().toString();
    const value = scValToNative(entry.val());
    argsMap.set(key, value);
  }
  
  const requiredArgs = [
    { key: "account", expected: expectedAccount },
    { key: "home_domain", expected: expectedHomeDomain },
    { key: "web_auth_domain", expected: expectedWebAuthDomain },
    { key: "web_auth_domain_account", expected: expectedWebAuthDomainAccount },
  ];
  
  for (const { key, expected } of requiredArgs) {
    const actual = argsMap.get(key);
    if (!actual) {
      throw new WebAuthError(`Missing required argument: ${key}`);
    }
    if (actual !== expected) {
      throw new WebAuthError(
        `Invalid argument ${key}. Expected '${expected}', got '${actual}'`
      );
    }
  }
  
  if (expectedClientDomain) {
    const clientDomain = argsMap.get("client_domain");
    if (!clientDomain) {
      throw new WebAuthError("Missing required argument: client_domain");
    }
    if (clientDomain !== expectedClientDomain) {
      throw new WebAuthError(
        `Invalid argument client_domain. Expected '${expectedClientDomain}', got '${clientDomain}'`
      );
    }
    
    if (expectedClientDomainAccount) {
      const clientDomainAccount = argsMap.get("client_domain_account");
      if (!clientDomainAccount) {
        throw new WebAuthError("Missing required argument: client_domain_account");
      }
      if (clientDomainAccount !== expectedClientDomainAccount) {
        throw new WebAuthError(
          `Invalid argument client_domain_account. Expected '${expectedClientDomainAccount}', got '${clientDomainAccount}'`
        );
      }
    }
  } else {
    if (argsMap.has("client_domain") || argsMap.has("client_domain_account")) {
      throw new WebAuthError("Unexpected client domain arguments provided");
    }
  }
  
  if (!argsMap.has("nonce")) {
    throw new WebAuthError("Missing required argument: nonce");
  }
}

/**
 * Determines if the authorization arguments include client domain information
 */
export function hasClientDomainInArgs(authEntry: xdr.SorobanAuthorizationEntry): boolean {
  const args = authEntry.rootInvocation().function().contractFn().args();
  if (args.length !== 1 || args[0].switch() !== xdr.ScValType.scvMap()) {
    return false;
  }
  
  const argEntries = args[0].map()!;
  
  for (const entry of argEntries) {
    const key = entry.key().sym().toString();
    if (key === "client_domain") {
      return true;
    }
  }
  
  return false;
}