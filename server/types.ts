/**
 * Request to generate a web authentication challenge
 */
export interface ChallengeRequest {
  /** The contract account address to authenticate */
  account: string;
  /** The home domain requesting authentication */
  home_domain: string;
  /** Optional client domain for multi-party authentication */
  client_domain?: string;
}

/**
 * Response containing the web authentication challenge
 * 
 * Contains authorization entries that must be signed by the client
 */
export interface ChallengeResponse {
  /** Base64-encoded XDR of Soroban authorization entries */
  authorization_entries: string;
  /** Network passphrase for the Stellar network */
  network_passphrase: string;
}

/**
 * Request to exchange signed authorization entries for a JWT token
 */
export interface TokenRequest {
  /** Base64-encoded XDR of signed authorization entries */
  authorization_entries: string;
}

/**
 * Response containing the authentication JWT token
 */
export interface TokenResponse {
  /** JWT token proving successful authentication */
  token: string;
}

/**
 * Configuration for the web authentication server
 */
export interface WebAuthConfig {
  /** Stellar network (TESTNET, MAINNET, etc.) */
  network: string;
  /** Contract ID for the web authentication contract */
  webAuthContractId: string;
  /** Secret key for transaction source account */
  sourceSigningKey: string;
  /** Secret key for server authentication signing */
  serverSigningKey: string;
  /** Soroban RPC endpoint URL */
  rpcUrl: string;
  /** Secret for JWT token signing */
  jwtSecret: string;
}

/**
 * Error response
 */
export interface ErrorResponse {
  /** Error code identifier */
  error: string;
  /** Human-readable error description */
  error_description: string;
}

/**
 * Custom error class for web authentication failures
 */
export class WebAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebAuthError";
  }
}

/**
 * Custom error class for SEP-45 protocol errors
 */
export class Sep45Error extends Error {
  constructor(
    public errorCode: string,
    public errorDescription: string,
    public httpStatus: number = 400,
  ) {
    super(errorDescription);
    this.name = "Sep45Error";
  }
}

/**
 * Parsed authorization entry arguments
 */
export interface AuthEntryArgs {
  account: string;
  home_domain: string;
  web_auth_domain: string;
  web_auth_domain_account: string;
  nonce: string;
  client_domain?: string;
  client_domain_account?: string;
}
