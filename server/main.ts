import "https://deno.land/std@0.201.0/dotenv/load.ts";
import { Application, Router, Context } from "jsr:@oak/oak";
import { getChallenge, getToken } from "./challenge.ts";
import {
  ChallengeRequest,
  ChallengeResponse,
  TokenRequest,
  TokenResponse,
  WebAuthError,
  Sep45Error,
  ErrorResponse,
} from "./types.ts";

const corsHandler = async (context: Context, next: () => Promise<unknown>) => {
  context.response.headers.set("Access-Control-Allow-Origin", "*");
  context.response.headers.set(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS",
  );
  context.response.headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization",
  );
  
  if (context.request.method === "OPTIONS") {
    context.response.status = 204;
    return;
  }
  
  await next();
};

const errorHandler = async (context: Context, next: () => Promise<unknown>) => {
  try {
    await next();
  } catch (error) {
    console.error("SEP-45 Server Error:", error);
    
    let response: ErrorResponse;
    let status: number;
    
    if (error instanceof Sep45Error) {
      status = error.httpStatus;
      response = {
        error: error.errorCode,
        error_description: error.errorDescription,
      };
    } else if (error instanceof WebAuthError) {
      status = 400;
      response = {
        error: "authentication_failed",
        error_description: error.message,
      };
    } else {
      status = 500;
      response = {
        error: "internal_server_error",
        error_description: "An internal server error occurred",
      };
    }
    
    context.response.status = status;
    context.response.body = response;
  }
};

const challengeHandler = async (context: Context) => {
  const params = context.request.url.searchParams;
  
  const account = params.get("account");
  const home_domain = params.get("home_domain");
  
  if (!account) {
    throw new Sep45Error(
      "invalid_request",
      "Missing required parameter: account",
      400,
    );
  }
  
  if (!home_domain) {
    throw new Sep45Error(
      "invalid_request",
      "Missing required parameter: home_domain",
      400,
    );
  }
  
  const request: ChallengeRequest = {
    account,
    home_domain,
    client_domain: params.get("client_domain") || undefined,
  };
  
  const response: ChallengeResponse = await getChallenge(request);
  context.response.status = 200;
  context.response.body = response;
};

const tokenHandler = async (context: Context) => {
  let body: Record<string, string>;
  
  // Support both JSON and form-encoded requests
  const contentType = context.request.headers.get("content-type") || "";
  
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const formData = await context.request.body.form();
    body = Object.fromEntries(formData);
  } else {
    body = await context.request.body.json();
  }
  
  if (!body.authorization_entries) {
    throw new Sep45Error(
      "invalid_request",
      "Missing required field: authorization_entries",
      400,
    );
  }
  
  const request: TokenRequest = {
    authorization_entries: body.authorization_entries,
  };
  
  const response: TokenResponse = await getToken(request);
  context.response.status = 200;
  context.response.body = response;
};

const router = new Router();
router
  .get("/challenge", challengeHandler)
  .post("/challenge", tokenHandler);

const app = new Application();

app.use(corsHandler);
app.use(errorHandler);
app.use(router.routes());
app.use(router.allowedMethods());

const PORT = parseInt(Deno.env.get("PORT") || "80");
console.log(`SEP-45 Web Authentication Server starting on port ${PORT}`);
app.listen({ port: PORT });
