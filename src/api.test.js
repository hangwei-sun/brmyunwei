import assert from "node:assert/strict";
import test from "node:test";
import { ApiError, clearAccessToken, getDashboard, login, normalizeDashboard, requestJson, setAccessToken } from "./api.js";

test("requestJson returns a successful JSON payload", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  }));
  assert.deepEqual(await requestJson("/api/health"), { ok: true });
});

test("requestJson exposes backend validation messages", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ error: "服务器名称已存在。" }), {
    status: 409,
    headers: { "Content-Type": "application/json" },
  }));
  await assert.rejects(requestJson("/api/hosts"), (error) => {
    assert.equal(error.message, "服务器名称已存在。");
    assert.equal(error.status, 409);
    return true;
  });
});

test("requestJson adds the bearer token to authenticated calls", async (t) => {
  setAccessToken("test-access-token");
  t.after(() => clearAccessToken());
  t.mock.method(globalThis, "fetch", async (_path, options) => {
    assert.equal(options.headers.get("Authorization"), "Bearer test-access-token");
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  await requestJson("/api/auth/me");
});

test("login stores the access token returned by the center service", async (t) => {
  clearAccessToken();
  t.after(() => clearAccessToken());
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ accessToken: "signed-token" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  }));
  const result = await login("admin", "password");
  assert.equal(result.accessToken, "signed-token");
});

test("requestJson normalizes network failures", async (t) => {
  t.mock.method(globalThis, "fetch", async () => { throw new TypeError("fetch failed"); });
  await assert.rejects(requestJson("/api/dashboard"), (error) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.status, 0);
    assert.match(error.message, /无法连接中心端/);
    return true;
  });
});

test("normalizeDashboard preserves API data and supplies a display event", () => {
  const dashboard = normalizeDashboard({
    hosts: [{ id: "WEB-01", ip: "10.0.0.1" }],
    incidents: [],
    ha: { failoverSupported: true, activeNode: "node-b" },
  });
  assert.equal(dashboard.hosts[0].event, "-");
  assert.equal(dashboard.isPrimary, false);
  assert.equal(dashboard.ha.activeNode, "node-b");
});

test("getDashboard rejects malformed successful responses", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ hosts: [] }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  }));
  await assert.rejects(getDashboard(), (error) => {
    assert.equal(error.status, 502);
    return true;
  });
});
