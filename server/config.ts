import { Networks, Keypair, Contract, SorobanRpc } from "npm:stellar-sdk";
import type { WebAuthConfig } from "./types.ts";

function validateEnvironment(): void {
  const required = [
    "NETWORK",
    "WEB_AUTH_CONTRACT_ID", 
    "SOURCE_SIGNING_KEY",
    "SERVER_SIGNING_KEY",
    "RPC_URL",
    "JWT_SECRET"
  ];
  
  const missing = required.filter(key => !Deno.env.get(key));
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
}

export function createConfig(): WebAuthConfig {
  validateEnvironment();
  
  return {
    network: Deno.env.get("NETWORK")!,
    webAuthContractId: Deno.env.get("WEB_AUTH_CONTRACT_ID")!,
    sourceSigningKey: Deno.env.get("SOURCE_SIGNING_KEY")!,
    serverSigningKey: Deno.env.get("SERVER_SIGNING_KEY")!,
    rpcUrl: Deno.env.get("RPC_URL")!,
    jwtSecret: Deno.env.get("JWT_SECRET")!,
  };
}

export function getNetwork(config: WebAuthConfig): string {
  const network = Networks[config.network as keyof typeof Networks];
  if (!network) {
    throw new Error(`Unsupported network: ${config.network}`);
  }
  return network;
}

export function init(config: WebAuthConfig) {
  const network = getNetwork(config);
  const webAuthContract = new Contract(config.webAuthContractId);
  const sourceKeypair = Keypair.fromSecret(config.sourceSigningKey);
  const serverKeypair = Keypair.fromSecret(config.serverSigningKey);
  const rpc = new SorobanRpc.Server(config.rpcUrl);
  
  return {
    network,
    webAuthContract,
    sourceKeypair,
    serverKeypair,
    rpc,
  };
}