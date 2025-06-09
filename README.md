# SEP-45 Reference Implementation

A complete reference implementation of [SEP-45 Web Authentication for Contract Accounts](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0045.md).

## Overview

This repository demonstrates how to implement SEP-45 web authentication for Stellar contract accounts. It includes both the server-side authentication service and the necessary Soroban smart contracts.

SEP-45 enables users to prove control of their contract accounts through cryptographic signatures, providing secure authentication without traditional username/password systems.

## Project Structure

```
sep45-reference/
├── server/                # Authentication server
│   ├── main.ts            # HTTP endpoints
│   ├── challenge.ts       # SEP-45 core logic
│   ├── types.ts           # Type definitions
│   ├── config.ts          # Configuration
│   ├── validation/        # Validation modules
│   └── challenge.test.ts  # Test suite
├── soroban/               # Smart contracts
│   └── contracts/
│       ├── web_auth/      # Authentication contract
│       └── account/       # Account contract for testing
└── README.md
```

## Architecture

### Components

1. **Authentication Server** (TypeScript/Deno)
   - Issues authentication challenges
   - Validates signed authorization entries
   - Generates JWT tokens for authenticated users

2. **Smart Contracts** (Rust/Soroban)
   - `web_auth`: Validates authentication
   - `account`: Custom account contract with ED25519 verification for testing

## Quick Start

### Prerequisites

- Deno
- Rust
- Stellar CLI

### Setup

```bash
git clone https://github.com/stellar/sep45-reference
cd sep45-reference

# Create .env file with required variables
cp .env.example .env

# Deploy contracts
# cd soroban/contracts/web_auth

# Start server
cd server
deno task dev
```

### Environment Variables

```bash
NETWORK=TESTNET
WEB_AUTH_CONTRACT_ID=your_contract_id
SOURCE_SIGNING_KEY=your_source_secret
SERVER_SIGNING_KEY=your_server_secret
RPC_URL=https://soroban-testnet.stellar.org
JWT_SECRET=your_jwt_secret

WALLET_ADDRESS=your_wallet_address
WALLET_SIGNER=your_wallet_signer
```

## API Reference

### Challenge Endpoint

```http
GET /challenge?account={CONTRACT_ADDRESS}&home_domain={DOMAIN}&client_domain={OPTIONAL_DOMAIN}
```

Required parameters per SEP-45:

- `account` - Contract account address to authenticate
- `home_domain` - Domain requesting authentication

Optional parameters:

- `client_domain` - For multi-party authentication

Response format per SEP-45:

```json
{
  "authorization_entries": "base64_encoded_xdr_entries",
  "network_passphrase": "Test SDF Network ; September 2015"
}
```

### Token Endpoint

```http
POST /challenge
Content-Type: application/json

{
  "authorization_entries": "base64_encoded_signed_xdr_entries"
}
```

Response per SEP-45:

```json
{
  "token": "jwt_token"
}
```

### Error Responses

All errors follow this format:

```json
{
  "error": "error_code",
  "error_description": "Human readable description"
}
```

Common error codes:

- `invalid_request` - Missing or invalid parameters
- `authentication_failed` - Invalid signatures or authorization entries

## Testing

```bash
cd server
# Direct command with required permissions
deno test --allow-read --allow-env --allow-net --unstable-kv

# Or use the task (equivalent to above)
deno task test
```
