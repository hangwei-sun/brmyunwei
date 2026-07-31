import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, Bell, CheckCircle2, ChevronDown, ChevronLeft,
  ChevronRight, Database, LockKeyhole, LogOut, Menu, Pencil, Plus,
  RefreshCw, Save, Search, Send, Server, Settings2, ShieldCheck, Trash2, Users, X, ExternalLink, ArrowLeftRight,
} from "lucide-react";
import {
  clearAccessToken, createNotificationPolicy, createUser, deleteNotificationPolicy, getAccessToken, getCurrentUser, getDashboard,
  getHaCluster, getInAppNotifications, getNotificationPolicies, getRules, getServerGroups, getSystemSettings, getUsers, login, markAllInAppNotificationsRead, markInAppNotificationRead, requestJson,
  sendTestSms, updateSystemSettings,
  updateNotificationPolicy, updateRule, updateUser,
} from "./api.js";

const MetricTrend = lazy(() => import("./Charts.jsx").then((module) => ({ default: module.MetricTrend })));
const baseNavItems = [["总览", Activity], ["资产", Server], ["事件", AlertTriangle], ["告警规则", Bell], ["通知", Send]];
const roleLabels = { Admin: "管理员", Operator: "运维员", Viewer: "只读用户" };

const isAdmin = (user) => user?.role === "Admin";
const isOperator = (user) => user?.role === "Admin" || user?.role === "Operator";
const formatTime = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "从未";

function StatusDot({ status }) {
  const kind = ["健康", "正常", "活动", "已启用"].includes(status) ? "green" : ["性能降级", "警告"].includes(status) ? "orange" : ["维护中"].includes(status) ? "blue" : ["确认离线", "业务异常", "故障", "严重"].includes(status) ? "red" : "gray";
  return <span className={`dot ${kind}`} />;
}

function Severity({ value }) { return <span className={`severity ${value === "严重" ? "critical" : "warning"}`}>{value}</span>; }

function MetricBar({ value }) {
  if (value == null) return <span className="muted">-</span>;
  const tone = value >= 90 ? "danger" : value >= 75 ? "warning" : "ok";
  return <span className={`metric ${tone}`}><b>{value}%</b><i><em style={{ width: `${Math.min(100, Math.max(0, value))}%` }} /></i></span>;
}

function PageState({ kind, message, onRetry, compact = false }) {
  const Icon = kind === "loading" ? RefreshCw : kind === "error" ? AlertTriangle : Database;
  return <div className={`data-state ${compact ? "compact" : ""} ${kind}`} role={kind === "error" ? "alert" : "status"}>
    <Icon className={kind === "loading" ? "spin" : ""} size={18} /><span>{message}</span>
    {onRetry && <button className="subtle-button" onClick={onRetry}><RefreshCw size={14} />重试</button>}
  </div>;
}

function LoginScreen({ onLogin }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [state, setState] = useState({ submitting: false, error: "" });
  const submit = async (event) => {
    event.preventDefault(); setState({ submitting: true, error: "" });
    try { await onLogin(form.username, form.password); }
    catch (error) { setState({ submitting: false, error: error.message }); }
  };
  return <main className="login-page"><section className="login-panel"><div className="login-brand"><Activity size={26} /><div><h1>机房运维监控</h1><p>使用运维账号登录中心端</p></div></div><form onSubmit={submit}><label>账号<input autoFocus autoComplete="username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} /></label><label>密码<input type="password" autoComplete="current-password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></label>{state.error && <div className="login-error" role="alert"><AlertTriangle size={16} />{state.error}</div>}<button className="primary-button login-submit" disabled={state.submitting || !form.username || !form.password}><LockKeyhole size={16} />{state.submitting ? "正在登录…" : "登录"}</button></form></section></main>;
}

function roleText(mode) { return mode === "active" ? "主用" : mode === "passive" ? "备用" : mode === "single-node" ? "单节点" : "未知"; }

function HaControlModal({ cluster, onClose }) {
  const current = cluster?.current;
  const peer = cluster?.peer;
  const openNode = (url) => { if (url) window.location.assign(url); };
  const hasPair = current?.enabled && peer;
  return <Modal wide title={hasPair ? "双节点控制端" : "控制端状态"} description={hasPair ? "管理入口可在两个控制端间切换。主备角色变更须经过 witness 租约与受控切换流程。" : "当前实例尚未完成双节点配置。"} onClose={onClose}>
    <div className="ha-control">
      {hasPair ? <><div className="ha-switch-track"><span><StatusDot status={current.holdsLease ? "活动" : "未知"} />{current.nodeId}</span><ArrowLeftRight size={17} /><span><StatusDot status={peer.ready ? "活动" : "未知"} />{peer.nodeId}</span></div><div className="ha-node-list">
        <section className={`ha-node ${current.holdsLease ? "is-writer" : ""}`}><div className="ha-node-heading"><div><b>{current.nodeId}</b><small>当前控制端</small></div><span className={`ha-role ${current.holdsLease ? "primary" : "standby"}`}>{roleText(current.mode)}</span></div><dl><dt>写入就绪</dt><dd>{current.holdsLease ? "ready" : "not-ready"}</dd><dt>Fencing epoch</dt><dd>{current.epoch ?? "-"}</dd><dt>租约到期</dt><dd>{formatTime(current.leaseExpiresAt)}</dd></dl><button className="subtle-button" disabled={!cluster.currentManagementUrl} onClick={() => openNode(cluster.currentManagementUrl)}><ExternalLink size={15} />当前节点</button></section>
        <section className={`ha-node ${peer.ready ? "is-writer" : ""}`}><div className="ha-node-heading"><div><b>{peer.nodeId}</b><small>对端控制端</small></div><span className={`ha-role ${peer.ready ? "primary" : "standby"}`}>{roleText(peer.role)}</span></div><dl><dt>写入就绪</dt><dd>{peer.ready ? "ready" : "not-ready"}</dd><dt>Fencing epoch</dt><dd>{peer.epoch ?? "-"}</dd><dt>检查时间</dt><dd>{formatTime(peer.checkedAt)}</dd></dl>{peer.error && <p className="ha-node-error">{peer.error}</p>}<button className="primary-button" disabled={!peer.managementUrl} onClick={() => openNode(peer.managementUrl)}><ArrowLeftRight size={15} />切换至该节点</button></section>
      </div><p className="ha-control-note">“切换至该节点”只切换浏览器连接的管理入口；计划切换、故障接管与回切仍由 witness fencing、自动监视器和受控提升脚本执行。</p></> : <div className="ha-unconfigured"><AlertTriangle size={19} /><div><b>双节点参数尚未配置</b><p>请在两个控制端的 HighAvailability 中配置本机和对端的 PublicUrl、PeerNodeId、PeerPublicUrl、PeerReadyUrl 后重新加载。</p></div></div>}
    </div>
  </Modal>;
}

function AppShell({ active, setActive, children, incidentCount, notificationCount, notificationsOpen, onToggleNotifications, onCloseNotifications, onNotificationsChanged, ha, haCluster, dataStatus, user, onLogout, siteName }) {
  const [collapsed, setCollapsed] = useState(false); const [haOpen, setHaOpen] = useState(false);
  const navItems = isAdmin(user) ? [...baseNavItems, ["设置", Settings2], ["用户", Users]] : baseNavItems;
  const status = haCluster?.current || ha;
  const statusText = status?.mode === "single-node" ? "单节点模式" : status?.enabled ? `双节点 · 本机${roleText(status.mode)}` : "中心端状态未知";
  return <div className={`app-shell ${collapsed ? "collapsed" : ""}`}><aside className="sidebar"><div className="brand"><Activity size={23} /><span>{siteName || "机房运维监控"}</span></div><nav>{navItems.map(([label, Icon]) => <button key={label} className={active === label ? "nav-active" : ""} onClick={() => setActive(label)}><Icon size={19} /><span>{label}</span>{label === "事件" && incidentCount > 0 && <b className="nav-badge">{incidentCount}</b>}</button>)}</nav><div className="sidebar-bottom"><span><StatusDot status="健康" /><span>{user.username}</span></span><button onClick={() => setCollapsed(!collapsed)} title="收起侧栏"><ChevronLeft size={18} /></button></div></aside><section className="workspace"><header className="topbar"><button className="icon-button mobile-menu"><Menu size={20} /></button><div className="room-select"><Database size={17} /> {siteName || "生产机房"} <ChevronDown size={15} /></div><div className="global-search" aria-label="全局搜索"><Search size={18} /><span>使用页面内筛选查找资产和事件</span></div><div className="topbar-status"><span><RefreshCw className={dataStatus === "loading" ? "spin" : ""} size={15} /> {dataStatus === "ready" ? "数据已同步" : dataStatus === "loading" ? "正在同步" : "中心端连接异常"}</span><button className="node-active node-status-button" onClick={() => setHaOpen(true)} aria-haspopup="dialog"><StatusDot status={status?.holdsLease ? "活动" : "未知"} />{statusText}</button></div><button className="icon-button notification" aria-label="打开站内信" aria-haspopup="dialog" aria-expanded={notificationsOpen} onClick={onToggleNotifications}><Bell size={19} />{notificationCount > 0 && <i>{notificationCount > 99 ? "99+" : notificationCount}</i>}</button><span className="user"><Users size={19} /> {user.username} · {roleLabels[user.role] || user.role}</span><button className="icon-button" onClick={onLogout} title="退出登录"><LogOut size={17} /></button></header><main className="page">{children}</main>{notificationsOpen && <NotificationCenter onClose={onCloseNotifications} onChanged={onNotificationsChanged} />}{haOpen && <HaControlModal cluster={haCluster} onClose={() => setHaOpen(false)} />}</section></div>;
}

function Modal({ title, description, children, onClose, wide = false }) {
  useEffect(() => { const closeOnEscape = (event) => { if (event.key === "Escape") onClose(); }; window.addEventListener("keydown", closeOnEscape); return () => window.removeEventListener("keydown", closeOnEscape); }, [onClose]);
  return <div className="modal-backdrop" role="presentation" onMouseDown={onClose}><section className={`modal ${wide ? "modal-wide" : ""}`} role="dialog" aria-modal="true" aria-label={title} onMouseDown={(event) => event.stopPropagation()}><div className="modal-heading"><div><h2>{title}</h2>{description && <p>{description}</p>}</div><button type="button" className="icon-button" onClick={onClose} aria-label="关闭"><X /></button></div>{children}</section></div>;
}

function notificationItems(payload) { return Array.isArray(payload) ? payload : Array.isArray(payload?.items) ? payload.items : []; }

function NotificationCenter({ onClose, onChanged }) {
  const [tab, setTab] = useState("unread");
  const [items, setItems] = useState([]);
  const [state, setState] = useState({ status: "loading", error: "" });
  const load = useCallback(async () => {
    setState({ status: "loading", error: "" });
    try {
      setItems(notificationItems(await getInAppNotifications(tab === "unread")));
      setState({ status: "ready", error: "" });
    } catch (error) { setState({ status: "error", error: error.message }); }
  }, [tab]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const closeOnEscape = (event) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  const markRead = async (item) => {
    if (item.readAt) return;
    try {
      await markInAppNotificationRead(item.id);
      setItems((current) => tab === "unread" ? current.filter((entry) => entry.id !== item.id) : current.map((entry) => entry.id === item.id ? { ...entry, readAt: new Date().toISOString() } : entry));
      onChanged();
    } catch (error) { setState({ status: "error", error: error.message }); }
  };
  const markAllRead = async () => {
    try {
      await markAllInAppNotificationsRead();
      setItems((current) => tab === "unread" ? [] : current.map((item) => ({ ...item, readAt: new Date().toISOString() })));
      onChanged();
    } catch (error) { setState({ status: "error", error: error.message }); }
  };
  return <div className="notification-backdrop" onMouseDown={onClose}><section className="notification-center" role="dialog" aria-modal="true" aria-label="站内信" onMouseDown={(event) => event.stopPropagation()}><div className="notification-heading"><div><h2>站内信</h2><p>告警事件会按通知策略发送到当前账号。</p></div><button className="icon-button" onClick={onClose} aria-label="关闭站内信"><X size={17} /></button></div><div className="notification-toolbar"><div className="notification-tabs" role="tablist" aria-label="站内信筛选"><button role="tab" aria-selected={tab === "unread"} className={tab === "unread" ? "selected" : ""} onClick={() => setTab("unread")}>未读</button><button role="tab" aria-selected={tab === "all"} className={tab === "all" ? "selected" : ""} onClick={() => setTab("all")}>全部</button></div><button className="text-button" disabled={items.length === 0} onClick={markAllRead}>全部标为已读</button></div>{state.status === "loading" ? <PageState kind="loading" compact message="正在加载站内信…" /> : state.status === "error" ? <PageState kind="error" compact message={state.error} onRetry={load} /> : items.length === 0 ? <PageState kind="empty" compact message={tab === "unread" ? "没有未读站内信。" : "暂时没有站内信。"} /> : <div className="notification-list">{items.map((item) => <button className={`notification-item ${item.readAt ? "is-read" : ""}`} key={item.id} onClick={() => markRead(item)} title={item.readAt ? "已读" : "点击标为已读"}><Severity value={item.severity || "警告"} /><span><strong>{item.title}</strong><small>{[item.hostName, item.policyName].filter(Boolean).join(" / ")}</small><p>{item.content}</p><time>{formatTime(item.createdAt)}</time></span>{!item.readAt && <i aria-label="未读" />}</button>)}</div>}</section></div>;
}

function Overview({ hosts, incidents, onOpenIncident, onOpenHost, setActive, dataState, onRetry }) {
  const [filters, setFilters] = useState({ q: "", status: "全部", room: "全部", service: "全部" });
  const rooms = useMemo(() => [...new Set(hosts.map((host) => host.room).filter(Boolean))], [hosts]);
  const services = useMemo(() => [...new Set(hosts.map((host) => host.service).filter(Boolean))], [hosts]);
  const shown = hosts.filter((host) => (filters.status === "全部" || host.status === filters.status) && (filters.room === "全部" || host.room === filters.room) && (filters.service === "全部" || host.service === filters.service) && `${host.id} ${host.ip} ${host.service}`.toLowerCase().includes(filters.q.toLowerCase()));
  const count = (status) => hosts.filter((host) => host.status === status).length;
  if (dataState.status === "loading") return <PageState kind="loading" message="正在从中心端加载监控数据…" />;
  if (dataState.status === "error") return <PageState kind="error" message={dataState.error} onRetry={onRetry} />;
  return <><div className="page-title"><div><h1>实时总览</h1><p>机房基础设施与业务系统运行状态概览</p></div><button className="text-button" onClick={() => setActive("事件")}>查看全部事件</button></div><section className="dashboard-grid"><div className="overview-main"><div className="summary-strip"><div><b>{hosts.length}</b><span>台服务器</span></div><div><StatusDot status="健康" /><b>{count("健康")}</b><span>健康</span></div><div><StatusDot status="性能降级" /><b>{count("性能降级")}</b><span>性能降级</span></div><div><StatusDot status="严重" /><b>{count("业务异常")}</b><span>业务异常</span></div><div><StatusDot status="严重" /><b>{count("确认离线")}</b><span>确认离线</span></div><div><StatusDot status="维护中" /><b>{count("维护中")}</b><span>维护中</span></div></div><div className="filters"><label><Search size={16} /><input value={filters.q} onChange={(event) => setFilters({ ...filters, q: event.target.value })} placeholder="搜索服务器（主机名 / IP）" /></label><select value={filters.room} onChange={(event) => setFilters({ ...filters, room: event.target.value })}><option>全部</option>{rooms.map((room) => <option key={room}>{room}</option>)}</select><select value={filters.service} onChange={(event) => setFilters({ ...filters, service: event.target.value })}><option>全部</option>{services.map((service) => <option key={service}>{service}</option>)}</select><select value={filters.status} onChange={(event) => setFilters({ ...filters, status: event.target.value })}><option>全部</option>{["健康", "性能降级", "业务异常", "确认离线", "维护中"].map((status) => <option key={status}>{status}</option>)}</select><button className="subtle-button" onClick={() => setFilters({ q: "", status: "全部", room: "全部", service: "全部" })}><RefreshCw size={15} />重置</button></div><HostTable hosts={shown} onOpenHost={onOpenHost} /><div className="table-footer">共 {shown.length} 条 <span><button className="icon-button" disabled><ChevronLeft size={16} /></button><button className="pager-current">1</button><button className="icon-button" disabled><ChevronRight size={16} /></button></span></div></div><aside className="right-rail"><section className="rail-card"><div className="card-heading"><h2>未确认事件 <b>{incidents.length}</b></h2><button className="text-button" onClick={() => setActive("事件")}>查看更多</button></div>{incidents.slice(0, 5).map((incident) => <button className="incident-row" key={incident.id} onClick={() => onOpenIncident(incident)}><span><StatusDot status={incident.severity} /><strong>{incident.title}</strong><small>{incident.host} / {incident.ip} · {incident.started}</small></span><span>详情</span></button>)}{incidents.length === 0 && <PageState kind="empty" compact message="当前没有未确认事件。" />}</section><section className="rail-card"><div className="card-heading"><h2>监控链路</h2></div><div className="health-row"><span>中心端 API</span><span><StatusDot status="正常" /> 正常</span></div><div className="health-row"><span>高可用能力</span><span>{dataState.status === "ready" ? "当前未启用" : "待确认"}</span></div></section></aside></section></>;
}

function HostTable({ hosts, onOpenHost, manage = false, onEdit, onDelete }) {
  return <div className="table-wrap host-table"><table><thead><tr><th>状态</th><th>主机名 / IP</th><th>服务器组</th><th>机房</th><th>业务系统</th><th>CPU</th><th>内存</th><th>磁盘</th><th>延迟</th><th>代理心跳</th>{manage && <th>操作</th>}</tr></thead><tbody>{hosts.map((host) => <tr key={host.id}><td><StatusDot status={host.status} /> {host.status}</td><td><button className="text-button" onClick={() => onOpenHost(host)}>{host.id}</button><small>{host.ip}</small></td><td>{host.group || "默认组"}</td><td>{host.room}</td><td>{host.service}</td><td><MetricBar value={host.cpu} /></td><td><MetricBar value={host.memory} /></td><td><MetricBar value={host.disk} /></td><td>{host.latency == null ? "-" : `${host.latency} ms`}</td><td>{host.heartbeat}</td>{manage && <td><button className="text-button" onClick={() => onOpenHost(host)}>详情</button><button className="text-button" onClick={() => onEdit(host)}>编辑</button><button className="text-button destructive" onClick={() => onDelete(host)}>删除</button></td>}</tr>)}</tbody></table>{hosts.length === 0 && <PageState kind="empty" compact message="没有符合当前条件的服务器。" />}</div>;
}

function IncidentDrawer({ incident, onClose, onUpdate, onOpenHost, canOperate }) {
  const [note, setNote] = useState("");
  const [state, setState] = useState({ saving: false, error: "" });
  if (!incident) return null;
  const run = async (action) => { setState({ saving: true, error: "" }); try { await onUpdate(incident.id, action, note); } catch (error) { setState({ saving: false, error: error.message }); } };
  return <div className="drawer-backdrop"><aside className="incident-drawer"><div className="drawer-title"><div><Severity value={incident.severity} /><h2>{incident.title}</h2></div><button className="icon-button" onClick={onClose}><X /></button></div><section><h3>事件概览</h3><dl><dt>主机名</dt><dd><button className="text-button" onClick={() => onOpenHost({ id: incident.host, ip: incident.ip })}>{incident.host} ({incident.ip})</button></dd><dt>事件类型</dt><dd>{incident.signal}</dd><dt>当前值</dt><dd>{incident.value}</dd><dt>开始时间</dt><dd>{incident.started}</dd><dt>持续时长</dt><dd>{incident.duration}</dd><dt>状态</dt><dd>{incident.state}</dd></dl></section>{canOperate && <><section><h3>处置备注</h3><textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="填写处置备注（可选）" maxLength={200} /><small>{note.length}/200</small>{state.error && <p className="form-error">{state.error}</p>}</section><div className="drawer-actions"><button className="danger-button" disabled={state.saving} onClick={() => run("确认")}>确认事件</button><button className="subtle-button" disabled={state.saving} onClick={() => run("静默")}>临时静默</button><button className="subtle-button" disabled={state.saving} onClick={() => run("维护")}>进入维护</button></div></>}</aside></div>;
}

function AssetDetail({ host, onBack }) {
  const [samples, setSamples] = useState([]); const [state, setState] = useState({ status: "loading", error: "" });
  const load = useCallback(async () => { if (!host?.id) return; setState({ status: "loading", error: "" }); try { const response = await requestJson(`/api/hosts/${encodeURIComponent(host.id)}/metrics`); setSamples(response.map((sample) => ({ time: new Date(sample.collectedAt).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" }), cpu: sample.cpu, memory: sample.memory, disk: sample.disk, latency: sample.latency }))); setState({ status: "ready", error: "" }); } catch (error) { setState({ status: "error", error: error.message }); } }, [host?.id]);
  useEffect(() => { load(); }, [load]);
  return <><div className="breadcrumb"><button onClick={onBack}>资产</button> / {host?.id}</div><section className="asset-header"><h1>{host?.id}</h1><span><StatusDot status={host?.status} /> {host?.status || "未知"}</span><dl><div><dt>IP</dt><dd>{host?.ip || "-"}</dd></div><div><dt>服务器组</dt><dd>{host?.group || "默认组"}</dd></div><div><dt>机房</dt><dd>{host?.room || "-"}</dd></div><div><dt>业务系统</dt><dd>{host?.service || "-"}</dd></div><div><dt>最后心跳</dt><dd>{host?.heartbeat || "-"}</dd></div></dl></section><section className="asset-grid"><div>{state.status === "loading" ? <PageState kind="loading" message="正在加载主机指标…" /> : state.status === "error" ? <PageState kind="error" message={state.error} onRetry={load} /> : samples.length === 0 ? <PageState kind="empty" message="该主机尚无指标样本。" /> : [["CPU 使用率 (%)", "cpu", "#1463df"], ["内存使用率 (%)", "memory", "#16a35a"], ["磁盘使用率 (%)", "disk", "#ef4444"], ["网络延迟 (ms)", "latency", "#9333ea"]].map(([name, dataKey, stroke]) => <section className="chart-panel" key={dataKey}><h2>{name}<small>最新：{host?.[dataKey] == null ? "-" : `${host[dataKey]}${dataKey === "latency" ? " ms" : "%"}`}</small></h2><Suspense fallback={<PageState kind="loading" compact message="正在加载图表…" />}><MetricTrend data={samples} dataKey={dataKey} stroke={stroke} /></Suspense></section>)}</div><aside><section className="side-info"><h2>监控健康</h2><p>Agent 心跳<span>{host?.heartbeat || "-"}</span></p><p>Agent 版本<span>{host?.agentVersion || "-"}</span></p><p>启动时间<span>{formatTime(host?.bootTime)}</span></p></section><section className="side-info"><h2>资产信息</h2>{[["主机名", host?.id], ["IP 地址", host?.ip], ["服务器组", host?.group], ["机房", host?.room], ["业务系统", host?.service], ["状态", host?.status]].map(([key, value]) => <p key={key}>{key}<span>{value || "-"}</span></p>)}</section></aside></section></>;
}

function RulesPage({ user }) {
  const [rules, setRules] = useState([]); const [state, setState] = useState({ status: "loading", error: "" }); const [editing, setEditing] = useState(null);
  const load = useCallback(async () => { setState({ status: "loading", error: "" }); try { setRules(await getRules()); setState({ status: "ready", error: "" }); } catch (error) { setState({ status: "error", error: error.message }); } }, []);
  useEffect(() => { load(); }, [load]);
  const save = async (rule) => { const saved = await updateRule(rule.id, rule); setRules((current) => current.map((item) => item.id === saved.id ? saved : item)); setEditing(null); };
  if (state.status === "loading") return <PageState kind="loading" message="正在加载告警规则…" />;
  if (state.status === "error") return <PageState kind="error" message={state.error} onRetry={load} />;
  return <><div className="page-title"><div><h1>告警规则</h1></div></div><div className="rules-layout"><section><div className="table-wrap"><table><thead><tr><th>启用</th><th>规则名称</th><th>检查项</th><th>警告阈值</th><th>严重阈值</th><th>触发 / 恢复</th><th>严重级别</th><th>更新时间</th>{isAdmin(user) && <th>操作</th>}</tr></thead><tbody>{rules.map((rule) => <tr key={rule.id}><td><StatusDot status={rule.enabled ? "已启用" : "已停用"} /> {rule.enabled ? "启用" : "停用"}</td><td>{rule.name}</td><td>{rule.checkItem}</td><td>{rule.warningThreshold}</td><td>{rule.criticalThreshold}</td><td>{rule.triggerCount} / {rule.recoveryCount}</td><td><Severity value={rule.severity} /></td><td>{formatTime(rule.updatedAt)}</td>{isAdmin(user) && <td><button className="text-button" onClick={() => setEditing(rule)}>编辑</button></td>}</tr>)}</tbody></table>{rules.length === 0 && <PageState kind="empty" compact message="中心端尚未配置告警规则。" />}</div></section></div>{editing && <RuleDrawer rule={editing} onClose={() => setEditing(null)} onSave={save} />}</>;
}

function RuleDrawer({ rule, onClose, onSave }) {
  const [form, setForm] = useState({ ...rule }); const [state, setState] = useState({ saving: false, error: "" });
  const submit = async (event) => { event.preventDefault(); setState({ saving: true, error: "" }); try { await onSave(form); } catch (error) { setState({ saving: false, error: error.message }); } };
  return <Modal title={`编辑规则 · ${rule.name}`} description="阈值变化只会影响后续采样判定。" onClose={onClose}><form className="modal-form" onSubmit={submit}><label className="toggle-field"><span>规则状态</span><button type="button" aria-label="切换规则" className={`toggle ${form.enabled ? "on" : ""}`} onClick={() => setForm({ ...form, enabled: !form.enabled })}><i /></button></label><div className="modal-grid"><label>警告阈值<input required type="number" value={form.warningThreshold} onChange={(event) => setForm({ ...form, warningThreshold: event.target.value })} /></label><label>严重阈值<input required type="number" value={form.criticalThreshold} onChange={(event) => setForm({ ...form, criticalThreshold: event.target.value })} /></label><label>连续触发次数<input required min="1" max="60" type="number" value={form.triggerCount} onChange={(event) => setForm({ ...form, triggerCount: event.target.value })} /></label><label>连续恢复次数<input required min="1" max="60" type="number" value={form.recoveryCount} onChange={(event) => setForm({ ...form, recoveryCount: event.target.value })} /></label></div>{state.error && <p className="form-error">{state.error}</p>}<div className="modal-actions"><button className="primary-button" disabled={state.saving}>{state.saving ? "正在保存…" : "保存"}</button><button type="button" className="subtle-button" onClick={onClose}>取消</button></div></form></Modal>;
}

function NotificationPage({ user }) {
  const [policies, setPolicies] = useState([]);
  const [groups, setGroups] = useState([]);
  const [state, setState] = useState({ status: "loading", error: "" });
  const [editing, setEditing] = useState(null);
  const load = useCallback(async () => { setState({ status: "loading", error: "" }); try { const [loadedPolicies, loadedGroups] = await Promise.all([getNotificationPolicies(), getServerGroups()]); setPolicies(loadedPolicies); setGroups(loadedGroups); setState({ status: "ready", error: "" }); } catch (error) { setState({ status: "error", error: error.message }); } }, []);
  useEffect(() => { load(); }, [load]);
  const save = async (policy) => { const saved = policy.isNew ? await createNotificationPolicy(policy) : await updateNotificationPolicy(policy.id, policy); setPolicies((current) => policy.isNew ? [...current, saved] : current.map((item) => item.id === saved.id ? saved : item)); setEditing(null); };
  const remove = async (policy) => { if (!window.confirm(`确定删除通知策略 ${policy.name} 吗？`)) return; await deleteNotificationPolicy(policy.id); setPolicies((current) => current.filter((item) => item.id !== policy.id)); };
  if (state.status === "loading") return <PageState kind="loading" message="正在加载通知策略…" />;
  if (state.status === "error") return <PageState kind="error" message={state.error} onRetry={load} />;
  return <>
    <div className="page-title"><div><h1>通知策略</h1><p>按服务器组和严重级别决定短信或本地站内信的投递范围。</p></div>{isAdmin(user) && <button className="primary-button" onClick={() => setEditing({ isNew: true, name: "", serverGroup: groups[0]?.name || "默认组", severity: "严重", channel: "sms", contactGroup: "", enabled: true, repeatMinutes: 15 })}><Plus size={16} />添加策略</button>}</div>
    <div className="rules-layout notification-policy-layout"><section><div className="table-wrap"><table><thead><tr><th>策略名称</th><th>通道</th><th>适用服务器组</th><th>严重级别</th><th>通知对象</th><th>重复提醒</th><th>状态</th><th>更新时间</th>{isAdmin(user) && <th>操作</th>}</tr></thead><tbody>{policies.map((policy) => {
      const inApp = policy.channel === "inApp";
      return <tr key={policy.id}><td>{policy.name}</td><td><span className={inApp ? "tag-enabled" : "tag-disabled"}>{inApp ? "站内信" : "腾讯云短信"}</span></td><td>{policy.serverGroup}</td><td><Severity value={policy.severity} /></td><td>{inApp ? "启用的管理员和运维人员" : policy.contactGroup}</td><td>{inApp ? "首次告警" : `${policy.repeatMinutes} 分钟`}</td><td><span className={policy.enabled ? "tag-enabled" : "tag-disabled"}>{policy.enabled ? "启用" : "停用"}</span></td><td>{formatTime(policy.updatedAt)}</td>{isAdmin(user) && <td><button className="text-button" onClick={() => setEditing(policy)}><Pencil size={14} />编辑</button><button className="text-button destructive" onClick={() => remove(policy)}><Trash2 size={14} />删除</button></td>}</tr>;
    })}</tbody></table>{policies.length === 0 && <PageState kind="empty" compact message="中心端尚未配置通知策略。" />}</div></section></div>
    {editing && <NotificationDrawer policy={editing} groups={groups} onClose={() => setEditing(null)} onSave={save} />}
  </>;
}

function NotificationDrawer({ policy, groups, onClose, onSave }) {
  const [form, setForm] = useState({ ...policy, channel: policy.channel || "sms" });
  const [state, setState] = useState({ saving: false, error: "" });
  const inApp = form.channel === "inApp";
  const submit = async (event) => {
    event.preventDefault();
    setState({ saving: true, error: "" });
    try { await onSave({ ...form, contactGroup: inApp ? "本地运维人员" : form.contactGroup }); }
    catch (error) { setState({ saving: false, error: error.message }); }
  };
  return <Modal title={policy.isNew ? "添加通知策略" : `编辑通知策略 · ${policy.name}`} description="按服务器组与严重级别匹配；站内信只在事件首次触发时投递一次。" onClose={onClose}><form className="modal-form" onSubmit={submit}><label>策略名称<input required autoFocus maxLength="80" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label><label>通知通道<select value={form.channel} onChange={(event) => setForm({ ...form, channel: event.target.value, contactGroup: event.target.value === "inApp" ? "本地运维人员" : form.contactGroup })}><option value="sms">腾讯云短信</option><option value="inApp">本地站内信</option></select></label><label>服务器组<select required value={form.serverGroup} onChange={(event) => setForm({ ...form, serverGroup: event.target.value })}>{groups.map((group) => <option value={group.name} key={group.name}>{group.name}（{group.hostCount} 台）</option>)}<option value="全部服务器">全部服务器</option></select></label><div className="modal-grid"><label>严重级别<select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })}><option>严重</option><option>警告</option></select></label>{inApp ? <label>站内接收范围<input disabled value="所有启用的管理员和运维人员" /></label> : <label>联系人组<input required maxLength="64" value={form.contactGroup} onChange={(event) => setForm({ ...form, contactGroup: event.target.value })} /></label>}</div><label className="toggle-field"><span>策略状态</span><button type="button" aria-label="切换通知策略" className={`toggle ${form.enabled ? "on" : ""}`} onClick={() => setForm({ ...form, enabled: !form.enabled })}><i /></button></label>{!inApp && <label>重复提醒间隔（分钟）<input required min="5" max="1440" type="number" value={form.repeatMinutes} onChange={(event) => setForm({ ...form, repeatMinutes: event.target.value })} /></label>}{state.error && <p className="form-error">{state.error}</p>}<div className="modal-actions"><button className="primary-button" disabled={state.saving}>{state.saving ? "正在保存…" : "保存"}</button><button type="button" className="subtle-button" onClick={onClose}>取消</button></div></form></Modal>;
}

function IncidentList({ incidents, onOpenIncident }) { return <><div className="page-title"><div><h1>事件管理</h1><p>查看、确认、静默和追踪中心端运行事件。</p></div></div><div className="table-wrap incident-table"><table><thead><tr><th>状态</th><th>严重级别</th><th>主机</th><th>事件类型</th><th>开始时间</th><th>持续时间</th><th>操作</th></tr></thead><tbody>{incidents.map((item) => <tr key={item.id}><td>{item.state}</td><td><Severity value={item.severity} /></td><td>{item.host}<small>{item.ip}</small></td><td>{item.title}</td><td>{item.started}</td><td>{item.duration}</td><td><button className="text-button" onClick={() => onOpenIncident(item)}>详情</button></td></tr>)}</tbody></table>{incidents.length === 0 && <PageState kind="empty" compact message="当前没有待处理事件。" />}</div></>;
}

function AssetsPage({ hosts, saveHost, deleteHost, openHost, user }) {
  const [query, setQuery] = useState(""); const [form, setForm] = useState(null); const [state, setState] = useState({ saving: false, error: "" }); const canManage = isAdmin(user);
  const groups = useMemo(() => [...new Set(hosts.map((host) => host.group).filter(Boolean))], [hosts]);
  const shown = hosts.filter((host) => `${host.id} ${host.ip} ${host.group} ${host.room} ${host.service}`.toLowerCase().includes(query.toLowerCase()));
  const submit = async (event) => { event.preventDefault(); setState({ saving: true, error: "" }); try { await saveHost(form); setForm(null); } catch (error) { setState({ saving: false, error: error.message }); } };
  return <><div className="page-title"><div><h1>资产管理</h1><p>按服务器组、机房和业务系统维护受监控资产。</p></div>{canManage && <button className="primary-button" onClick={() => { setState({ saving: false, error: "" }); setForm({ id: "", ip: "", group: groups[0] || "默认组", room: "", service: "", isNew: true }); }}><Plus size={16} />添加服务器</button>}</div><div className="filters"><label><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索主机名、IP、服务器组、机房或业务系统" /></label><button className="subtle-button" onClick={() => setQuery("")}>重置</button></div><HostTable hosts={shown} onOpenHost={openHost} manage={canManage} onEdit={(host) => { setState({ saving: false, error: "" }); setForm({ ...host, originalName: host.id }); }} onDelete={deleteHost} />{form && <Modal title={form.isNew ? "添加服务器" : `编辑服务器 · ${form.id}`} description="保存后将立即用于资产分组、监控和通知策略匹配。" onClose={() => setForm(null)}><form className="modal-form" onSubmit={submit}><label>服务器名称<input required autoFocus value={form.id} onChange={(event) => setForm({ ...form, id: event.target.value })} /></label><label>IP 地址<input required value={form.ip} onChange={(event) => setForm({ ...form, ip: event.target.value })} /></label><label>服务器组<input required list="server-groups" value={form.group} onChange={(event) => setForm({ ...form, group: event.target.value })} /><datalist id="server-groups">{groups.map((group) => <option key={group} value={group} />)}</datalist></label><label>机房<input required value={form.room} onChange={(event) => setForm({ ...form, room: event.target.value })} /></label><label>业务系统<input required value={form.service} onChange={(event) => setForm({ ...form, service: event.target.value })} /></label>{state.error && <p className="form-error">{state.error}</p>}<div className="modal-actions"><button className="primary-button" disabled={state.saving}>{state.saving ? "正在保存…" : "保存"}</button><button type="button" className="subtle-button" onClick={() => setForm(null)}>取消</button></div></form></Modal>}</>;
}

function UsersPage() {
  const [users, setUsers] = useState([]); const [state, setState] = useState({ status: "loading", error: "" }); const [editing, setEditing] = useState(null);
  const load = useCallback(async () => { setState({ status: "loading", error: "" }); try { setUsers(await getUsers()); setState({ status: "ready", error: "" }); } catch (error) { setState({ status: "error", error: error.message }); } }, []);
  useEffect(() => { load(); }, [load]);
  const save = async (form) => { const saved = form.isNew ? await createUser(form) : await updateUser(form.username, form); setUsers((current) => form.isNew ? [...current, saved].sort((a, b) => a.username.localeCompare(b.username)) : current.map((item) => item.username === saved.username ? saved : item)); setEditing(null); };
  if (state.status === "loading") return <PageState kind="loading" message="正在加载本地账号…" />;
  if (state.status === "error") return <PageState kind="error" message={state.error} onRetry={load} />;
  return <><div className="page-title"><div><h1>用户与权限</h1><p>管理员可维护本地账号及角色。角色变更或停用会使该账号现有会话失效。</p></div><button className="primary-button" onClick={() => setEditing({ isNew: true, username: "", role: "Viewer", enabled: true, password: "" })}><Plus size={16} />添加账号</button></div><div className="table-wrap"><table><thead><tr><th>账号</th><th>角色</th><th>最近登录</th><th>创建时间</th><th>状态</th><th>操作</th></tr></thead><tbody>{users.map((entry) => <tr key={entry.username}><td>{entry.username}</td><td>{roleLabels[entry.role] || entry.role}</td><td>{formatTime(entry.lastLoginAt)}</td><td>{formatTime(entry.createdAt)}</td><td><span className={entry.enabled ? "tag-enabled" : "tag-disabled"}>{entry.enabled ? "启用" : "停用"}</span></td><td><button className="text-button" onClick={() => setEditing({ ...entry, password: "" })}><Pencil size={14} />编辑</button></td></tr>)}</tbody></table>{users.length === 0 && <PageState kind="empty" compact message="尚未创建额外账号。" />}</div>{editing && <UserDrawer user={editing} onClose={() => setEditing(null)} onSave={save} />}</>;
}

function UserDrawer({ user, onClose, onSave }) {
  const [form, setForm] = useState({ ...user }); const [state, setState] = useState({ saving: false, error: "" });
  const submit = async (event) => { event.preventDefault(); setState({ saving: true, error: "" }); try { await onSave(form); } catch (error) { setState({ saving: false, error: error.message }); } };
  return <Modal title={form.isNew ? "添加账号" : `编辑账号 · ${form.username}`} description={form.isNew ? "创建后请通过受控方式交付初始密码。" : "角色变更或停用会使该账号的现有会话失效。"} onClose={onClose}><form className="modal-form" onSubmit={submit}><label>账号<input required disabled={!form.isNew} autoFocus value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} /></label><label>角色<select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>{Object.entries(roleLabels).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>{!form.isNew && <label className="toggle-field"><span>账号状态</span><button type="button" aria-label="切换账号状态" className={`toggle ${form.enabled ? "on" : ""}`} onClick={() => setForm({ ...form, enabled: !form.enabled })}><i /></button></label>}<label>{form.isNew ? "初始密码" : "重设密码（留空表示不修改）"}<input required={form.isNew} minLength="12" type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></label>{state.error && <p className="form-error">{state.error}</p>}<div className="modal-actions"><button className="primary-button" disabled={state.saving}>{state.saving ? "正在保存…" : "保存"}</button><button type="button" className="subtle-button" onClick={onClose}>取消</button></div></form></Modal>;
}

function settingsFormFrom(value) {
  return {
    siteName: value.siteName,
    siteDescription: value.siteDescription || "",
    sms: { ...value.sms, secretId: "", secretKey: "", clearSecretId: false, clearSecretKey: false },
  };
}

function SettingsPage({ onSaved, onOpenNotifications }) {
  const [tab, setTab] = useState("general"); const [form, setForm] = useState(null); const [groups, setGroups] = useState([]); const [state, setState] = useState({ status: "loading", saving: false, error: "", message: "" });
  const load = useCallback(async () => { setState({ status: "loading", saving: false, error: "", message: "" }); try { const [settings, serverGroups] = await Promise.all([getSystemSettings(), getServerGroups()]); setForm(settingsFormFrom(settings)); setGroups(serverGroups); setState({ status: "ready", saving: false, error: "", message: "" }); } catch (error) { setState({ status: "error", saving: false, error: error.message, message: "" }); } }, []);
  useEffect(() => { load(); }, [load]);
  const changeSms = (changes) => setForm({ ...form, sms: { ...form.sms, ...changes } });
  const save = async (event) => { event.preventDefault(); setState({ ...state, saving: true, error: "", message: "" }); try { const saved = await updateSystemSettings(form); setForm(settingsFormFrom(saved)); onSaved(saved); setState({ status: "ready", saving: false, error: "", message: "设置已保存，短信配置会立即用于后续投递。" }); } catch (error) { setState({ status: "ready", saving: false, error: error.message, message: "" }); } };
  const testSms = async () => { setState({ ...state, saving: true, error: "", message: "" }); try { const result = await sendTestSms(form.sms.testPhoneNumbers); setState({ status: "ready", saving: false, error: "", message: `测试短信已提交，请求号：${result.requestId || "已受理"}` }); } catch (error) { setState({ status: "ready", saving: false, error: error.message, message: "" }); } };
  if (state.status === "loading") return <PageState kind="loading" message="正在读取系统设置…" />;
  if (state.status === "error" || !form) return <PageState kind="error" message={state.error || "无法读取系统设置。"} onRetry={load} />;
  const smsReady = form.sms.secretIdConfigured && form.sms.secretKeyConfigured && form.sms.sdkAppId && form.sms.signName && form.sms.templateId;
  return <><div className="page-title"><div><h1>系统设置</h1><p>维护站点信息、腾讯云短信投放方式，以及各服务器组的通知策略范围。</p></div></div><div className="settings-layout"><nav className="settings-tabs" aria-label="设置分类"><button className={tab === "general" ? "selected" : ""} onClick={() => setTab("general")}>通用设置</button><button className={tab === "sms" ? "selected" : ""} onClick={() => setTab("sms")}>腾讯云短信</button><button className={tab === "scope" ? "selected" : ""} onClick={() => setTab("scope")}>通知范围</button></nav><section className="settings-panel">{tab === "general" && <form className="settings-form" onSubmit={save}><div className="settings-section"><h2>站点标识</h2><p>显示在侧边栏与顶部，用于区分当前控制端。</p><label>站点名称<input required maxLength="80" value={form.siteName} onChange={(event) => setForm({ ...form, siteName: event.target.value })} /></label><label>站点说明<textarea maxLength="160" value={form.siteDescription} onChange={(event) => setForm({ ...form, siteDescription: event.target.value })} /></label></div><SettingsFeedback state={state} /><div className="settings-actions"><button className="primary-button" disabled={state.saving}><Save size={16} />{state.saving ? "正在保存…" : "保存通用设置"}</button></div></form>}{tab === "sms" && <form className="settings-form" onSubmit={save}><div className="settings-section"><div className="settings-section-title"><div><h2>腾讯云短信</h2><p>密钥在本机加密保存，读取接口不会回显。建议始终先使用测试模式。</p></div><span className={`tag-${form.sms.enabled ? "enabled" : "disabled"}`}>{form.sms.enabled ? form.sms.rolloutMode : "disabled"}</span></div><label className="toggle-field"><span><b>启用短信通道</b><small>关闭后不会调用腾讯云。</small></span><button type="button" className={`toggle ${form.sms.enabled ? "on" : ""}`} aria-label="切换短信通道" onClick={() => changeSms({ enabled: !form.sms.enabled })}><i /></button></label><div className="modal-grid"><label>投放模式<select value={form.sms.rolloutMode} onChange={(event) => changeSms({ rolloutMode: event.target.value })}><option value="disabled">disabled（不发送）</option><option value="test">test（仅测试号码）</option><option value="live">live（真实联系人）</option></select></label><label>地域<input required value={form.sms.region} onChange={(event) => changeSms({ region: event.target.value })} placeholder="ap-guangzhou" /></label><label>SDK AppID<input value={form.sms.sdkAppId} onChange={(event) => changeSms({ sdkAppId: event.target.value })} /></label><label>短信签名<input value={form.sms.signName} onChange={(event) => changeSms({ signName: event.target.value })} /></label><label>模板 ID<input value={form.sms.templateId} onChange={(event) => changeSms({ templateId: event.target.value })} /></label><label>SecretId<input disabled={form.sms.clearSecretId} autoComplete="off" placeholder={form.sms.secretIdConfigured ? "已配置，留空不修改" : "输入腾讯云 SecretId"} value={form.sms.secretId} onChange={(event) => changeSms({ secretId: event.target.value, clearSecretId: false })} /></label><label className="span-two">SecretKey<input disabled={form.sms.clearSecretKey} type="password" autoComplete="new-password" placeholder={form.sms.secretKeyConfigured ? "已配置，留空不修改" : "输入腾讯云 SecretKey"} value={form.sms.secretKey} onChange={(event) => changeSms({ secretKey: event.target.value, clearSecretKey: false })} /></label></div><div className="secret-controls">{form.sms.secretIdConfigured && <label><input type="checkbox" checked={form.sms.clearSecretId} onChange={(event) => changeSms({ clearSecretId: event.target.checked, secretId: "" })} />清除已保存的 SecretId</label>}{form.sms.secretKeyConfigured && <label><input type="checkbox" checked={form.sms.clearSecretKey} onChange={(event) => changeSms({ clearSecretKey: event.target.checked, secretKey: "" })} />清除已保存的 SecretKey</label>}</div><label>测试号码<textarea value={form.sms.testPhoneNumbers.join("\n")} onChange={(event) => changeSms({ testPhoneNumbers: event.target.value.split(/[\s,;]+/).filter(Boolean) })} placeholder={"每行一个 E.164 号码，例如 +8613800000000"} /></label><div className="settings-note">当前策略按“服务器组 + 严重级别”匹配；停用策略只影响后续事件，不会为当前未恢复事件补发短信。</div></div><SettingsFeedback state={state} /><div className="settings-actions"><button className="primary-button" disabled={state.saving}><Save size={16} />{state.saving ? "正在保存…" : "保存短信设置"}</button><button type="button" className="outline-button" disabled={state.saving || !form.sms.enabled || form.sms.rolloutMode !== "test" || !smsReady || form.sms.testPhoneNumbers.length === 0} onClick={testSms}>发送测试短信</button></div></form>}{tab === "scope" && <section className="settings-form"><div className="settings-section"><div className="settings-section-title"><div><h2>服务器组与通知策略</h2><p>资产所属服务器组决定哪些设备会命中对应的通知策略。</p></div><button className="primary-button" onClick={onOpenNotifications}><Bell size={16} />管理通知策略</button></div><div className="group-scope-list">{groups.map((group) => <div className="group-scope-row" key={group.name}><div><b>{group.name}</b><small>{group.hostCount} 台资产</small></div><span>策略范围依据该组匹配</span></div>)}{groups.length === 0 && <PageState kind="empty" compact message="尚未创建服务器组。" />}</div></div><div className="settings-note">要调整某一批设备的通知范围，请先在资产管理中设置服务器组，再在通知策略中选择同名服务器组。</div></section>}</section></div></>;
}

function SettingsFeedback({ state }) {
  return <>{state.error && <p className="form-error" role="alert">{state.error}</p>}{state.message && <p className="form-success" role="status">{state.message}</p>}</>;
}

export function App() {
  const [session, setSession] = useState({ status: getAccessToken() ? "checking" : "anonymous", user: null }); const [active, setActive] = useState("总览"); const [hosts, setHosts] = useState([]); const [incidents, setIncidents] = useState([]); const [drawer, setDrawer] = useState(null); const [selectedHost, setSelectedHost] = useState(null); const [ha, setHa] = useState(null); const [haCluster, setHaCluster] = useState(null); const [dataState, setDataState] = useState({ status: "loading", error: "" }); const [systemSettings, setSystemSettings] = useState(null); const [notificationCount, setNotificationCount] = useState(0); const [notificationsOpen, setNotificationsOpen] = useState(false);
  const loadDashboard = useCallback(async () => { setDataState({ status: "loading", error: "" }); try { const [dashboard, cluster] = await Promise.all([getDashboard(), getHaCluster()]); setHosts(dashboard.hosts); setIncidents(dashboard.incidents); setHa(dashboard.ha); setHaCluster(cluster); setDataState({ status: "ready", error: "" }); } catch (error) { setDataState({ status: "error", error: error.message }); } }, []);
  useEffect(() => { if (session.status !== "checking") return; getCurrentUser().then((user) => setSession({ status: "authenticated", user })).catch(() => { clearAccessToken(); setSession({ status: "anonymous", user: null }); }); }, [session.status]);
  useEffect(() => { if (session.status === "authenticated") loadDashboard(); }, [loadDashboard, session.status]);
  const refreshNotificationCount = useCallback(async () => { try { setNotificationCount(notificationItems(await getInAppNotifications(true)).length); } catch { /* Notification center exposes loading failures when opened. */ } }, []);
  useEffect(() => { if (session.status !== "authenticated") return; refreshNotificationCount(); const timer = window.setInterval(refreshNotificationCount, 30000); return () => window.clearInterval(timer); }, [refreshNotificationCount, session.status]);
  useEffect(() => { if (session.status !== "authenticated" || !isAdmin(session.user)) return; getSystemSettings().then(setSystemSettings).catch(() => {}); }, [session.status, session.user]);
  const authenticate = async (username, password) => { await login(username, password); setSession({ status: "authenticated", user: await getCurrentUser() }); };
  const logout = () => { clearAccessToken(); setSession({ status: "anonymous", user: null }); setHosts([]); setIncidents([]); setSelectedHost(null); setDrawer(null); setHaCluster(null); setSystemSettings(null); setNotificationCount(0); setNotificationsOpen(false); };
  const openHost = (host) => { setSelectedHost({ ...hosts.find((item) => item.id === host.id), ...host }); setDrawer(null); };
  const updateIncident = async (id, action, note) => { const operation = action === "确认" ? "acknowledge" : action === "静默" ? "silence" : "maintenance"; await requestJson(`/api/incidents/${id}/${operation}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ note: note || null }) }); setDrawer(null); await loadDashboard(); };
  const saveHost = async (host) => { const saved = await requestJson(host.originalName ? `/api/hosts/${encodeURIComponent(host.originalName)}` : "/api/hosts", { method: host.originalName ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: host.id, ip: host.ip, group: host.group, room: host.room, service: host.service }) }); setHosts((current) => host.originalName ? current.map((item) => item.id === host.originalName ? { ...saved, event: "-" } : item) : [...current, { ...saved, event: "-" }].sort((left, right) => left.id.localeCompare(right.id))); };
  const deleteHost = async (host) => { if (!window.confirm(`确定删除服务器 ${host.id} 吗？该操作会删除其指标样本。`)) return; try { await requestJson(`/api/hosts/${encodeURIComponent(host.id)}`, { method: "DELETE" }); setHosts((current) => current.filter((item) => item.id !== host.id)); } catch (error) { window.alert(error.message); } };
  if (session.status === "checking") return <PageState kind="loading" message="正在验证登录状态…" />;
  if (session.status !== "authenticated") return <LoginScreen onLogin={authenticate} />;
  let content = <Overview hosts={hosts} incidents={incidents} onOpenIncident={setDrawer} onOpenHost={openHost} setActive={setActive} dataState={dataState} onRetry={loadDashboard} />;
  if (selectedHost) content = <AssetDetail host={selectedHost} onBack={() => setSelectedHost(null)} />;
  else if (active === "资产") content = <AssetsPage hosts={hosts} saveHost={saveHost} deleteHost={deleteHost} openHost={openHost} user={session.user} />;
  else if (active === "事件") content = <IncidentList incidents={incidents} onOpenIncident={setDrawer} />;
  else if (active === "告警规则") content = <RulesPage user={session.user} />;
  else if (active === "通知") content = <NotificationPage user={session.user} />;
  else if (active === "设置" && isAdmin(session.user)) content = <SettingsPage onSaved={setSystemSettings} onOpenNotifications={() => setActive("通知")} />;
  else if (active === "用户" && isAdmin(session.user)) content = <UsersPage />;
  return <AppShell active={active} setActive={(next) => { setSelectedHost(null); setActive(next); }} incidentCount={incidents.length} notificationCount={notificationCount} notificationsOpen={notificationsOpen} onToggleNotifications={() => setNotificationsOpen((open) => !open)} onCloseNotifications={() => setNotificationsOpen(false)} onNotificationsChanged={refreshNotificationCount} ha={ha} haCluster={haCluster} dataStatus={dataState.status} user={session.user} onLogout={logout} siteName={systemSettings?.siteName}>{content}<IncidentDrawer incident={drawer} onClose={() => setDrawer(null)} onUpdate={updateIncident} onOpenHost={openHost} canOperate={isOperator(session.user)} /></AppShell>;
}
