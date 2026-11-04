import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { afterAll, beforeAll, expect, it } from "vitest";

// Build and exercise the actual HTTP entrypoint without external WEEEK calls.
let child: ChildProcess;
let origin: string;
let accessToken: string;
beforeAll(async () => {
  execFileSync(process.execPath, ["node_modules/typescript/bin/tsc", "-p", "tsconfig.json"]);
  // PORT=0 lets the operating system choose a free port.
  child = spawn(process.execPath, ["dist/http-server.js"], {
    env: { ...process.env, PORT: "0", MCP_ACCESS_CODE: "integration-test-code", WEEEK_API_TOKEN: "t".repeat(24) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`Server exited: ${code}`)));
    child.stderr!.on("data", (data: Buffer) => {
      const match = data.toString().match(/listening on http:\/\/0\.0\.0\.0:(\d+)\/mcp/);
      if (match) { origin = `http://127.0.0.1:${match[1]}`; resolve(); }
    });
  });
  const verifier = "v".repeat(64);
  const response = await fetch(origin + "/authorize", {
    method: "POST", redirect: "manual",
    body: new URLSearchParams({ client_id: "test-client", redirect_uri: "https://example.com/callback", code_challenge: createHash("sha256").update(verifier).digest("base64url"), access_code: "integration-test-code" }),
  });
  expect(response.status).toBe(302);
  const code = new URL(response.headers.get("location")!).searchParams.get("code")!;
  const token = await fetch(origin + "/token", { method: "POST", body: new URLSearchParams({ grant_type: "authorization_code", client_id: "test-client", redirect_uri: "https://example.com/callback", code, code_verifier: verifier }) });
  expect(token.status).toBe(200);
  accessToken = (await token.json() as { access_token: string }).access_token;
}, 20_000);
afterAll(async () => { if (child && child.exitCode === null) { child.kill(); await once(child, "exit"); } });

async function rpc(method: string, params: unknown = {}) {
  const response = await fetch(origin + "/mcp", {
    method: "POST", headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await response.text();
  expect(response.status, text).toBe(200);
  const data = response.headers.get("content-type")?.includes("text/event-stream") ? text.split("\n").find((line) => line.startsWith("data: "))!.slice(6) : text;
  return JSON.parse(data);
}
it("handles initialize, repeated tools/list and concurrent requests with reused JSON-RPC IDs", async () => {
  const initialized = await rpc("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "regression-test", version: "1" } });
  expect(initialized.result.serverInfo).toBeDefined();
  for (let i = 0; i < 3; i++) expect((await rpc("tools/list")).result.tools.length).toBeGreaterThan(0);
  const parallel = await Promise.all([rpc("tools/list"), rpc("tools/list")]);
  expect(parallel[0].result.tools).toEqual(parallel[1].result.tools);
});
it("continues to reject unauthenticated requests", async () => {
  const response = await fetch(origin + "/mcp", { method: "POST" });
  expect(response.status).toBe(401);
  expect(response.headers.get("www-authenticate")).toContain("resource_metadata");
});
