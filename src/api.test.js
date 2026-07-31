import assert from "node:assert/strict";
import test from "node:test";
import { ApiError, clearAccessToken, getDashboard, getInAppNotifications, getSystemSettings, login, markAllInAppNotificationsRead, markInAppNotificationRead, normalizeDashboard, requestJson, setAccessToken, updateNotificationPolicy, updateRule, updateSystemSettings, updateUser } from "./api.js";

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

test("updateRule serializes only the alert-rule update contract", async (t) => {
  t.mock.method(globalThis, "fetch", async (path, options) => {
    assert.equal(path, "/api/rules/12");
    assert.equal(options.method, "PUT");
    assert.deepEqual(JSON.parse(options.body), { enabled: false, warningThreshold: 80, criticalThreshold: 90, triggerCount: 5, recoveryCount: 2 });
    return new Response(JSON.stringify({ id: 12 }), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  await updateRule(12, { enabled: false, warningThreshold: "80", criticalThreshold: "90", triggerCount: "5", recoveryCount: "2", ignored: "not sent" });
});

test("notification and user updates use their documented PUT contracts", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (path, options) => {
    calls.push([path, JSON.parse(options.body)]);
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  await updateNotificationPolicy(3, { name: "严重告警", serverGroup: "生产组", severity: "严重", contactGroup: "值班组", channel: "inApp", enabled: true, repeatMinutes: "20" });
  await updateUser("ops name", { role: "Operator", enabled: false, password: "" });
  assert.deepEqual(calls, [
    ["/api/notification-policies/3", { name: "严重告警", serverGroup: "生产组", severity: "严重", contactGroup: "值班组", channel: "inApp", enabled: true, repeatMinutes: 20 }],
    ["/api/users/ops%20name", { role: "Operator", enabled: false, password: null }],
  ]);
});

test("system settings save sends secrets only on write and reads the settings endpoint", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (path, options = {}) => {
    calls.push([path, options.method || "GET", options.body ? JSON.parse(options.body) : null]);
    return new Response(JSON.stringify({ siteName: "机房运维监控", sms: {} }), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  await getSystemSettings();
  await updateSystemSettings({ siteName: "预发布机房", siteDescription: "说明", sms: { enabled: true, rolloutMode: "test", region: "ap-guangzhou", sdkAppId: "1400000000", signName: "运维平台", templateId: "100001", testPhoneNumbers: ["+8613800000000"], secretId: "id", secretKey: "key", clearSecretId: false, clearSecretKey: false } });
  assert.deepEqual(calls, [
    ["/api/settings", "GET", null],
    ["/api/settings", "PUT", { siteName: "预发布机房", siteDescription: "说明", smsEnabled: true, rolloutMode: "test", region: "ap-guangzhou", sdkAppId: "1400000000", signName: "运维平台", templateId: "100001", testPhoneNumbers: ["+8613800000000"], secretId: "id", secretKey: "key", clearSecretId: false, clearSecretKey: false }],
  ]);
});

test("in-app notification API uses unread filtering and read commands", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (path, options = {}) => {
    calls.push([path, options.method || "GET"]);
    return new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  await getInAppNotifications(true);
  await markInAppNotificationRead("notice / 1");
  await markAllInAppNotificationsRead();
  assert.deepEqual(calls, [
    ["/api/in-app-notifications?unreadOnly=true", "GET"],
    ["/api/in-app-notifications/notice%20%2F%201/read", "POST"],
    ["/api/in-app-notifications/read-all", "POST"],
  ]);
});
