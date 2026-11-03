import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

const AUTH_TTL_MS = 10 * 60_000;
const TOKEN_TTL_MS = 60 * 60_000;
type AuthorizationCode = { clientId: string; redirectUri: string; codeChallenge: string; expiresAt: number };
type AccessToken = { expiresAt: number };
function randomSecret(): string { return randomBytes(32).toString("base64url"); }
function html(value: string): string { return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!); }
async function body(req: IncomingMessage): Promise<URLSearchParams> { let text = ""; for await (const chunk of req) text += chunk; return new URLSearchParams(text); }

export class PrivateOAuth {
  private readonly codes = new Map<string, AuthorizationCode>();
  private readonly tokens = new Map<string, AccessToken>();
  constructor(private readonly accessCode: string | undefined) {}
  configured(): boolean { return Boolean(this.accessCode); }
  isAuthorized(header: string | undefined): boolean {
    if (!header?.startsWith("Bearer ")) return false;
    const token = this.tokens.get(header.slice("Bearer ".length));
    return Boolean(token && token.expiresAt > Date.now());
  }
  challenge(res: ServerResponse, origin: string, path: string): void {
    res.writeHead(401, { "content-type": "application/json", "www-authenticate": "Bearer resource_metadata=\"" + origin + "/.well-known/oauth-protected-resource" + path + "\"" });
    res.end(JSON.stringify({ error: "unauthorized" }));
  }
  metadata(origin: string, mcpPath: string): Record<string, unknown> {
    return { resource: origin + mcpPath, authorization_servers: [origin], scopes_supported: ["weeek:manage"], bearer_methods_supported: ["header"] };
  }
  authorizationMetadata(origin: string): Record<string, unknown> {
    return { issuer: origin, authorization_endpoint: origin + "/authorize", token_endpoint: origin + "/token", registration_endpoint: origin + "/register", response_types_supported: ["code"], grant_types_supported: ["authorization_code"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], scopes_supported: ["weeek:manage"] };
  }
  async authorize(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    if (!this.configured()) return this.error(res, 503, "server_misconfigured", "MCP_ACCESS_CODE is not configured");
    if (req.method === "GET") {
      const clientId = url.searchParams.get("client_id") ?? "";
      const redirectUri = url.searchParams.get("redirect_uri") ?? "";
      const state = url.searchParams.get("state") ?? "";
      const challenge = url.searchParams.get("code_challenge") ?? "";
      const method = url.searchParams.get("code_challenge_method") ?? "";
      if (!clientId || !redirectUri || !challenge || method !== "S256") return this.error(res, 400, "invalid_request", "PKCE S256 authorization parameters are required");
      try { new URL(redirectUri); } catch { return this.error(res, 400, "invalid_request", "invalid redirect_uri"); }
      const page = '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Freedom Pro — WEEEK</title></head><body><main><h1>Freedom Pro — WEEEK</h1><p>Подтвердите подключение приложения к корпоративному WEEEK.</p><form method="post" action="/authorize"><input type="hidden" name="client_id" value="' + html(clientId) + '"><input type="hidden" name="redirect_uri" value="' + html(redirectUri) + '"><input type="hidden" name="state" value="' + html(state) + '"><input type="hidden" name="code_challenge" value="' + html(challenge) + '"><label>Код доступа <input type="password" name="access_code" autofocus required></label><button type="submit">Подключить</button></form></main></body></html>';
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }); res.end(page); return;
    }
    if (req.method !== "POST") return this.error(res, 405, "method_not_allowed", "Use GET or POST");
    const form = await body(req);
    const clientId = form.get("client_id") ?? ""; const redirectUri = form.get("redirect_uri") ?? ""; const state = form.get("state") ?? ""; const challenge = form.get("code_challenge") ?? ""; const supplied = form.get("access_code") ?? "";
    if (!clientId || !redirectUri || !challenge || !this.matches(supplied)) return this.error(res, 401, "access_denied", "Invalid access code");
    try { new URL(redirectUri); } catch { return this.error(res, 400, "invalid_request", "invalid redirect_uri"); }
    const code = randomSecret(); this.codes.set(code, { clientId, redirectUri, codeChallenge: challenge, expiresAt: Date.now() + AUTH_TTL_MS });
    const location = new URL(redirectUri); location.searchParams.set("code", code); if (state) location.searchParams.set("state", state);
    res.writeHead(302, { location: location.toString(), "cache-control": "no-store" }); res.end();
  }
  async token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== "POST") return this.error(res, 405, "method_not_allowed", "Use POST");
    const form = await body(req); const code = form.get("code") ?? ""; const grant = this.codes.get(code); const verifier = form.get("code_verifier") ?? ""; const clientId = form.get("client_id") ?? ""; const redirectUri = form.get("redirect_uri") ?? "";
    this.codes.delete(code); const challenge = createHash("sha256").update(verifier).digest("base64url");
    if (form.get("grant_type") !== "authorization_code" || !grant || grant.expiresAt <= Date.now() || grant.clientId !== clientId || grant.redirectUri !== redirectUri || grant.codeChallenge !== challenge) return this.error(res, 400, "invalid_grant", "Authorization grant is invalid or expired");
    const accessToken = randomSecret(); this.tokens.set(accessToken, { expiresAt: Date.now() + TOKEN_TTL_MS });
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify({ access_token: accessToken, token_type: "Bearer", expires_in: TOKEN_TTL_MS / 1000, scope: "weeek:manage" }));
  }
  register(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== "POST") return this.error(res, 405, "method_not_allowed", "Use POST");
    res.writeHead(201, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify({ client_id: randomSecret(), token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"] }));
  }
  private matches(value: string): boolean { if (!this.accessCode) return false; const left = Buffer.from(value); const right = Buffer.from(this.accessCode); return left.length === right.length && timingSafeEqual(left, right); }
  private error(res: ServerResponse, status: number, error: string, description: string): void { res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify({ error, error_description: description })); }
}
