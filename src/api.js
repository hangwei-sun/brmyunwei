export class ApiError extends Error {
  constructor(message, status = 0, details = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

const TOKEN_KEY = "monitoring-platform.access-token";
let accessToken = typeof sessionStorage === "undefined" ? null : sessionStorage.getItem(TOKEN_KEY);

export function getAccessToken() {
  return accessToken;
}

export function setAccessToken(token) {
  accessToken = token || null;
  if (typeof sessionStorage === "undefined") return;
  if (accessToken) sessionStorage.setItem(TOKEN_KEY, accessToken);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export function clearAccessToken() {
  setAccessToken(null);
}

export async function requestJson(path, options = {}) {
  let response;
  try {
    const headers = new Headers(options.headers || {});
    if (accessToken && !headers.has("Authorization")) headers.set("Authorization", `Bearer ${accessToken}`);
    response = await fetch(path, { ...options, headers });
  } catch (error) {
    throw new ApiError("无法连接中心端，请检查服务和网络。", 0, error);
  }

  const payload = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    const message = payload?.error
      || payload?.detail
      || payload?.title
      || payload?.errors?.host?.[0]
      || `请求失败（HTTP ${response.status}）`;
    throw new ApiError(message, response.status, payload);
  }
  return payload;
}

export async function login(username, password) {
  const payload = await requestJson("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!payload?.accessToken) throw new ApiError("中心端未返回登录令牌。", 502, payload);
  setAccessToken(payload.accessToken);
  return payload;
}

export function getCurrentUser() {
  return requestJson("/api/auth/me");
}

export function normalizeDashboard(payload) {
  if (!payload || !Array.isArray(payload.hosts) || !Array.isArray(payload.incidents)) {
    throw new ApiError("中心端返回的仪表盘数据格式无效。", 502, payload);
  }

  return {
    hosts: payload.hosts.map((host) => ({ ...host, event: host.event || "-" })),
    incidents: payload.incidents,
    ha: payload.ha || null,
    isPrimary: payload.ha?.failoverSupported ? payload.ha.activeNode === "node-a" : true,
  };
}

export async function getDashboard() {
  return normalizeDashboard(await requestJson("/api/dashboard"));
}

export const getRules = () => requestJson("/api/rules");
export const updateRule = (id, rule) => requestJson(`/api/rules/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    enabled: rule.enabled,
    warningThreshold: Number(rule.warningThreshold),
    criticalThreshold: Number(rule.criticalThreshold),
    triggerCount: Number(rule.triggerCount),
    recoveryCount: Number(rule.recoveryCount),
  }),
});

export const getNotificationPolicies = () => requestJson("/api/notification-policies");
const notificationPolicyBody = (policy) => ({
  name: policy.name,
  serverGroup: policy.serverGroup,
  severity: policy.severity,
  contactGroup: policy.contactGroup,
  enabled: policy.enabled,
  repeatMinutes: Number(policy.repeatMinutes),
});
export const createNotificationPolicy = (policy) => requestJson("/api/notification-policies", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(notificationPolicyBody(policy)),
});
export const updateNotificationPolicy = (id, policy) => requestJson(`/api/notification-policies/${id}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(notificationPolicyBody(policy)),
});
export const deleteNotificationPolicy = (id) => requestJson(`/api/notification-policies/${id}`, { method: "DELETE" });

export const getSystemSettings = () => requestJson("/api/settings");
export const getServerGroups = () => requestJson("/api/settings/server-groups");
export const updateSystemSettings = (settings) => requestJson("/api/settings", {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    siteName: settings.siteName,
    siteDescription: settings.siteDescription,
    smsEnabled: settings.sms.enabled,
    rolloutMode: settings.sms.rolloutMode,
    region: settings.sms.region,
    sdkAppId: settings.sms.sdkAppId,
    signName: settings.sms.signName,
    templateId: settings.sms.templateId,
    testPhoneNumbers: settings.sms.testPhoneNumbers,
    secretId: settings.sms.secretId || null,
    secretKey: settings.sms.secretKey || null,
    clearSecretId: settings.sms.clearSecretId,
    clearSecretKey: settings.sms.clearSecretKey,
  }),
});
export const sendTestSms = (phoneNumbers) => requestJson("/api/notifications/test-sms", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ phoneNumbers, templateParameters: ["测试主机", "设置页测试短信", "正常", new Date().toLocaleString("zh-CN", { hour12: false })] }),
});

export const getUsers = () => requestJson("/api/users");
export const createUser = (user) => requestJson("/api/users", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: user.username, password: user.password, role: user.role }),
});
export const updateUser = (username, user) => requestJson(`/api/users/${encodeURIComponent(username)}`, {
  method: "PUT",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ role: user.role, enabled: user.enabled, password: user.password || null }),
});
