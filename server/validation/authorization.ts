import { xdr, StrKey, scValToNative } from "npm:stellar-sdk";
import { Buffer } from "node:buffer";
import { WebAuthError } from "../types.ts";

/**
 * Validates that authorization entries contain the correct contract address
 */
export function validateContractAddress(
  authEntry: xdr.SorobanAuthorizationEntry,
  expectedContractId: string
): void {
  const contractAddress = authEntry.rootInvocation().function().contractFn().contractAddress();
  
  if (contractAddress.switch() === xdr.ScAddressType.scAddressTypeContract()) {
    const actualContractId = contractAddress.contractId();
    const actualStrKey = StrKey.encodeContract(Buffer.from(actualContractId as Uint8Array));
    
    if (actualStrKey !== expectedContractId) {
      throw new WebAuthError(
        `Invalid contract address. Expected ${expectedContractId}, got ${actualStrKey}`
      );
    }
  } else {
    throw new WebAuthError(
      `Invalid address type. Expected contract address, got ${contractAddress.switch().name}`
    );
  }
}

/**
 * Validates that authorization entries call the correct function
 */
export function validateFunctionName(authEntry: xdr.SorobanAuthorizationEntry): void {
  const functionName = authEntry.rootInvocation().function().contractFn().functionName().toString();
  
  if (functionName !== "web_auth_verify") {
    throw new WebAuthError(
      `Invalid function name. Expected 'web_auth_verify', got '${functionName}'`
    );
  }
}

/**
 * Validates the basic structure of authorization entries
 */
export function validateAuthEntryStructure(authEntries: xdr.SorobanAuthorizationEntry[]): void {
  if (authEntries.length === 0) {
    throw new WebAuthError("No authorization entries provided");
  }
  
  // Check for sub-invocations (should not exist for web_auth_verify)
  for (const entry of authEntries) {
    const subInvocations = entry.rootInvocation().subInvocations();
    if (subInvocations.length > 0) {
      throw new WebAuthError("Authorization entries must not contain sub-invocations");
    }
  }
}

/**
 * Validates that all authorization entries have consistent arguments
 */
export function validateConsistentArguments(authEntries: xdr.SorobanAuthorizationEntry[]): void {
  if (authEntries.length < 2) return;
  
  // Get arguments from the first entry as reference
  const firstEntry = authEntries[0];
  const firstArgs = firstEntry.rootInvocation().function().contractFn().args();
  if (firstArgs.length !== 1 || firstArgs[0].switch() !== xdr.ScValType.scvMap()) {
    return; // Already validated elsewhere
  }
  
  const firstArgEntries = firstArgs[0].map()!;
  const firstArgsMap = new Map<string, string>();
  
  for (const entry of firstArgEntries) {
    const key = entry.key().sym().toString();
    const value = scValToNative(entry.val());
    firstArgsMap.set(key, value);
  }
  
  // Validate that all other entries have the same arguments
  for (let i = 1; i < authEntries.length; i++) {
    const entry = authEntries[i];
    const args = entry.rootInvocation().function().contractFn().args();
    
    if (args.length !== 1 || args[0].switch() !== xdr.ScValType.scvMap()) {
      throw new WebAuthError(`Authorization entry ${i} has invalid arguments structure`);
    }
    
    const argEntries = args[0].map()!;
    const argsMap = new Map<string, string>();
    
    for (const argEntry of argEntries) {
      const key = argEntry.key().sym().toString();
      const value = scValToNative(argEntry.val());
      argsMap.set(key, value);
    }
    
    // Check that all arguments match
    for (const [key, expectedValue] of firstArgsMap) {
      const actualValue = argsMap.get(key);
      if (actualValue !== expectedValue) {
        throw new WebAuthError(
          `Inconsistent argument '${key}' in authorization entry ${i}. Expected '${expectedValue}', got '${actualValue}'`
        );
      }
    }
    
    // Check that no extra arguments exist
    for (const key of argsMap.keys()) {
      if (!firstArgsMap.has(key)) {
        throw new WebAuthError(
          `Unexpected argument '${key}' in authorization entry ${i}`
        );
      }
    }
  }
}

/**
 * Helper function to convert ScAddress to string using proper XDR methods
 */
function scAddressToString(address: xdr.ScAddress): string {
  if (address.switch() === xdr.ScAddressType.scAddressTypeAccount()) {
    return StrKey.encodeEd25519PublicKey(Buffer.from(address.accountId().ed25519() as Uint8Array));
  } else if (address.switch() === xdr.ScAddressType.scAddressTypeContract()) {
    return StrKey.encodeContract(Buffer.from(address.contractId() as Uint8Array));
  } else {
    throw new WebAuthError(`Unsupported address type: ${address.switch().name}`);
  }
}

/**
 * Validates authorization entry signatures according to SEP-45 requirements
 * 
 * Ensures that all required parties have signed their respective authorization entries:
 * - Server must have a signed authorization entry
 * - Client must have an authorization entry (signature will be verified during simulation)
 * - Client domain (if present) must have an authorization entry
 */
export function validateAuthorizationEntrySignatures(
  authEntries: xdr.SorobanAuthorizationEntry[],
  expectedAccount: string,
  expectedWebAuthDomainAccount: string,
  expectedClientDomainAccount?: string
): void {
  let foundServerEntry = false;
  let foundClientEntry = false;
  let foundClientDomainEntry = false;
  
  for (const entry of authEntries) {
    const credentials = entry.credentials();
    
    if (credentials.switch() === xdr.SorobanCredentialsType.sorobanCredentialsAddress()) {
      const addressCred = credentials.address();
      const address = addressCred.address();
      
      try {
        const accountId = scAddressToString(address);
        
        // Check if this is the server's authorization entry
        if (accountId === expectedWebAuthDomainAccount) {
          foundServerEntry = true;
          
          // Verify the server's signature exists
          const signature = addressCred.signature();
          if (!signature) {
            throw new WebAuthError("Server authorization entry missing signature");
          }
        }
        
        // Check if this is the client's authorization entry
        if (accountId === expectedAccount) {
          foundClientEntry = true;
        }
        
        // Check if this is the client domain's authorization entry (if expected)
        if (expectedClientDomainAccount && accountId === expectedClientDomainAccount) {
          foundClientDomainEntry = true;
        }
      } catch (error) {
        // If we can't convert the address, skip this entry but continue validation
        console.warn("Failed to convert address in authorization entry:", error);
        continue;
      }
    }
  }
  
  // Verify required entries were found
  if (!foundServerEntry) {
    throw new WebAuthError(
      `Missing authorization entry for server account: ${expectedWebAuthDomainAccount}`
    );
  }
  
  if (!foundClientEntry) {
    throw new WebAuthError(
      `Missing authorization entry for client account: ${expectedAccount}`
    );
  }
  
  if (expectedClientDomainAccount && !foundClientDomainEntry) {
    throw new WebAuthError(
      `Missing authorization entry for client domain account: ${expectedClientDomainAccount}`
    );
  }
}