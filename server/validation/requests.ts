import { WebAuthError } from "../types.ts";
import type { ChallengeRequest, TokenRequest } from "../types.ts";

/**
 * Validates a challenge request has all required parameters
 */
export function validateChallengeRequest(request: Partial<ChallengeRequest>): void {
  if (!request.account || request.account.trim() === "") {
    throw new WebAuthError("Missing required parameter: account");
  }
  
  if (!request.home_domain || request.home_domain.trim() === "") {
    throw new WebAuthError("Missing required parameter: home_domain");
  }
}

/**
 * Validates a token request has all required parameters
 */
export function validateTokenRequest(request: Partial<TokenRequest>): void {
  if (!request.authorization_entries || request.authorization_entries.trim() === "") {
    throw new WebAuthError("Missing required parameter: authorization_entries");
  }
}