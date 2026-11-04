#!/usr/bin/env node
import { createServer } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { loadConfig } from "./config.js";
import { PrivateOAuth } from "./oauth.js";
import { buildServer } from "./server.js";

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const MCP_PATH = process.env.MCP_PATH ?? "/mcp";

function originFor(req: import("node:http").IncomingMessage): string {
  const host = req.headers.host ?? "localhost";
  const forwarded = req.headers["x-forwarded-proto"];
  const protocol = (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(",")[0] ?? "http";
  return protocol + "://" + host;
}

async function main(): Promise<void> {
  const config = loadConfig();
  if (!config.token) console.error("weeek-mcp-smart: WEEEK_API_TOKEN not set — calls will fail until it is provided.");
  const oauth = new PrivateOAuth(process.env.MCP_ACCESS_CODE);
  if (!oauth.configured()) console.error("weeek-mcp-smart: MCP_ACCESS_CODE not set — remote access is disabled.");
  const httpServer = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://" + (req.headers.host ?? "localhost"));
    const origin = originFor(req);
    if (url.pathname === "/health") {
      res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ ok: true })); return;
    }
    if (url.pathname === "/.well-known/oauth-protected-resource" || url.pathname === "/.well-known/oauth-protected-resource" + MCP_PATH) {
      res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(oauth.metadata(origin, MCP_PATH))); return;
    }
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(oauth.authorizationMetadata(origin))); return;
    }
    if (url.pathname === "/authorize") { await oauth.authorize(req, res, url); return; }
    if (url.pathname === "/token") { await oauth.token(req, res); return; }
    if (url.pathname === "/register") { oauth.register(req, res); return; }
    if (url.pathname !== MCP_PATH) {
      res.writeHead(404, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "Not found" })); return;
    }
    if (!oauth.configured() || !oauth.isAuthorized(req.headers.authorization)) {
      oauth.challenge(res, origin, MCP_PATH); return;
    }
    // Stateless transports may handle only one request, including across clients.
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    const server = buildServer(config);
    transport.onerror = (error) => console.error("weeek-mcp-smart transport error: " + error.message);
    res.once("close", () => {
      void server.close().catch((error: Error) => console.error("weeek-mcp-smart cleanup failed: " + error.message));
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res);
    }
    catch (error) {
      console.error("weeek-mcp-smart HTTP request failed: " + (error as Error).message);
      if (!res.headersSent) { res.writeHead(500, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "Internal server error" })); }
    }
  });
  httpServer.listen(PORT, "0.0.0.0", () => {
    const address = httpServer.address();
    const port = address && typeof address === "object" ? address.port : PORT;
    console.error("weeek-mcp-smart listening on http://0.0.0.0:" + port + MCP_PATH);
  });
}
main().catch((error) => { console.error("weeek-mcp-smart failed to start: " + (error as Error).message); process.exit(1); });
