import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import {
  Activity, AlertTriangle, Bell, CheckCircle2, ChevronDown, ChevronLeft,
  ChevronRight, CircleHelp, Database, Filter, Gauge, Laptop, LockKeyhole,
  LogOut, Menu, MoreHorizontal, Network, PauseCircle, RefreshCw, Search,
  Send, Server, ShieldCheck, SlidersHorizontal, Users, X, Zap,
} from "lucide-react";
import { clearAccessToken, getAccessToken, getCurrentUser, getDashboard, login, requestJson } from "./api.js";

const MetricTrend = lazy(() => import("./Charts.jsx").then((module) => ({ default: module.MetricTrend })));

const rules = [
  ["CPU 使用率 >90% 持续 5 分钟", "CPU 使用率", "> 90% / 5 分钟", "严重"],
  ["内存使用率 >90% 持续 5 分钟", "内存使用率", "> 90% / 5 分钟", "严重"],
  ["磁盘可用空间 <15%（警告）", "磁盘可用空间", "< 15% / 60 秒", "警告"],
  ["磁盘可用空间 <8%（严重）", "磁盘可用空间", "< 8% / 60 秒", "严重"],
  ["HTTP 连续 3 次失败", "HTTP(S)", "失败 3 次 / 5 分钟", "严重"],
  ["指定服务连续 2 次停止", "Windows 服务", "停止 2 次 / 5 分钟", "严重"],
];

const navItems = [
  ["总览", Laptop], ["资产", Server], ["事件", AlertTriangle], ["告警规则", Bell], ["通知", Send],
];

function StatusDot({ status }) {
  const kind = status === "健康" || status === "正常" || status === "活动" ? "green" : status === "性能降级" || status === "警告" ? "orange" : status === "维护中" ? "blue" : status === "确认离线" || status === "严重" ? "red" : "gray";
  return <span className={`dot ${kind}`} />;
}

function MetricBar({ value }) {
  if (value == null) return <span className="muted">-</span>;
  const tone = value >= 90 ? "danger" : value >= 75 ? "warning" : "ok";
  return <span className={`metric ${tone}`}><b>{value}%</b><i><em style={{ width: `${value}%` }} /></i></span>;
}

function Severity({ value }) { return <span className={`severity ${value === "严重" ? "critical" : "warning"}`}>{value}</span>; }

function PageState({ kind, message, onRetry, compact = false }) {
  return <div className={`data-state ${compact ? "compact" : ""} ${kind}`} role={kind === "error" ? "alert" : "status"}>
    {kind === "loading" ? <RefreshCw className="spin" size={18} /> : kind === "error" ? <AlertTriangle size={18} /> : <Database size={18} />}
    <span>{message}</span>{onRetry && <button className="subtle-button" onClick={onRetry}><RefreshCw size={14} />重试</button>}
  </div>;
}

function LoginScreen({ onLogin }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [state, setState] = useState({ submitting: false, error: "" });
  const submit = async (event) => {
    event.preventDefault();
    setState({ submitting: true, error: "" });
    try { await onLogin(form.username, form.password); }
    catch (error) { setState({ submitting: false, error: error.message }); }
  };
  return <main className="login-page"><section className="login-panel"><div className="login-brand"><Activity size={26} /><div><h1>机房运维监控</h1><p>使用运维账号登录中心端</p></div></div><form onSubmit={submit}><label>账号<input autoFocus autoComplete="username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} /></label><label>密码<input type="password" autoComplete="current-password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></label>{state.error && <div className="login-error" role="alert"><AlertTriangle size={16} />{state.error}</div>}<button className="primary-button login-submit" disabled={state.submitting || !form.username || !form.password}><LockKeyhole size={16} />{state.submitting ? "正在登录…" : "登录"}</button></form></section></main>;
}

function AppShell({ active, setActive, children, incidentCount, isPrimary, ha, dataStatus, user, onLogout }) {
  const [collapsed, setCollapsed] = useState(false);
  return <div className={`app-shell ${collapsed ? "collapsed" : ""}`}>
    <aside className="sidebar">
      <div className="brand"><Activity size={23} /><span>机房运维监控</span></div>
      <nav>{navItems.map(([label, Icon]) => <button key={label} className={active === label ? "nav-active" : ""} onClick={() => setActive(label)}><Icon size={19} /><span>{label}</span>{label === "事件" && incidentCount > 0 && <b className="nav-badge">{incidentCount}</b>}</button>)}</nav>
      <div className="sidebar-bottom"><span><StatusDot status="健康" /> <span>{user.username}</span></span><button onClick={() => setCollapsed(!collapsed)} title="收起侧栏"><ChevronLeft size={18} /></button></div>
    </aside>
    <section className="workspace">
      <header className="topbar">
        <button className="icon-button mobile-menu"><Menu size={20} /></button>
        <div className="room-select"><Database size={17} /> 生产机房 <ChevronDown size={15} /></div>
        <label className="global-search"><Search size={18} /><input placeholder="搜索主机名、IP、业务系统、检查项" /></label>
        <div className="topbar-status"><span><RefreshCw className={dataStatus === "loading" ? "spin" : ""} size={15} /> {dataStatus === "ready" ? "数据已同步" : dataStatus === "loading" ? "正在同步" : "中心端连接异常"}</span>{ha?.failoverSupported ? <><span className={isPrimary ? "node-active" : "node-wait"}><StatusDot status={isPrimary ? "活动" : "待命"} />主节点 · {isPrimary ? "活动" : "待命"}</span><span className={isPrimary ? "node-wait" : "node-active"}><StatusDot status={!isPrimary ? "活动" : "待命"} />备节点 · {!isPrimary ? "活动" : "待命"}</span></> : <span className="node-active"><StatusDot status="健康" />单节点模式</span>}</div>
        <button className="icon-button notification"><Bell size={19} />{incidentCount > 0 && <i>{incidentCount}</i>}</button><CircleHelp size={20} /><span className="user"><Users size={19} /> {user.username} · {user.role}</span><button className="icon-button" onClick={onLogout} title="退出登录"><LogOut size={17} /></button>
      </header>
      <main className="page">{children}</main>
    </section>
  </div>;
}

function Overview({ hosts, incidents, onOpenIncident, onOpenHost, setActive, dataState, onRetry, isPrimary, ha }) {
  const [filters, setFilters] = useState({ q: "", status: "全部" });
  const shown = hosts.filter((host) => (filters.status === "全部" || host.status === filters.status) && `${host.id} ${host.ip} ${host.service}`.toLowerCase().includes(filters.q.toLowerCase()));
  const counts = { total: hosts.length, healthy: hosts.filter((h) => h.status === "健康").length, warning: hosts.filter((h) => h.status === "性能降级").length, bad: hosts.filter((h) => h.status === "业务异常").length, offline: hosts.filter((h) => h.status === "确认离线").length, maintain: hosts.filter((h) => h.status === "维护中").length };
  if (dataState.status === "loading") return <PageState kind="loading" message="正在从中心端加载监控数据…" />;
  if (dataState.status === "error") return <PageState kind="error" message={dataState.error} onRetry={onRetry} />;
  return <>
    <div className="page-title"><div><h1>实时总览</h1><p>机房基础设施与业务系统运行状态概览</p></div><button className="text-button" onClick={() => setActive("事件")}>查看全部事件</button></div>
    <section className="dashboard-grid">
      <div className="overview-main">
        <div className="summary-strip"><div><b>{counts.total}</b><span>台服务器</span></div><div><StatusDot status="健康" /><b>{counts.healthy}</b><span>健康</span></div><div><StatusDot status="性能降级" /><b>{counts.warning}</b><span>性能降级</span></div><div><StatusDot status="严重" /><b>{counts.bad}</b><span>业务异常</span></div><div><StatusDot status="严重" /><b>{counts.offline}</b><span>确认离线</span></div><div><StatusDot status="维护中" /><b>{counts.maintain}</b><span>维护中</span></div></div>
        <div className="filters"><label><Search size={16} /><input value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} placeholder="搜索服务器（主机名 / IP）" /></label><select><option>全部机房</option></select><select><option>全部业务系统</option></select><select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}><option>全部</option><option>健康</option><option>性能降级</option><option>业务异常</option><option>确认离线</option></select><button className="subtle-button" onClick={() => setFilters({ q: "", status: "全部" })}><RefreshCw size={15} /> 重置</button></div>
        <div className="table-wrap host-table"><table><thead><tr><th>状态</th><th>主机名 / IP</th><th>机房</th><th>业务系统</th><th>CPU</th><th>内存</th><th>磁盘</th><th>延迟</th><th>代理心跳</th><th>最近事件</th></tr></thead><tbody>{shown.map((host) => <tr key={host.id} onClick={() => onOpenHost(host)}><td><StatusDot status={host.status} /> {host.status}</td><td><a>{host.id}</a><small>{host.ip}</small></td><td>{host.room}</td><td>{host.service}</td><td><MetricBar value={host.cpu} /></td><td><MetricBar value={host.memory} /></td><td><MetricBar value={host.disk} /></td><td>{host.latency ? `${host.latency} ms` : "-"}</td><td><StatusDot status={host.heartbeat === "失联" ? "严重" : "健康"} /> {host.heartbeat}</td><td className={host.event !== "-" ? "event-cell" : ""}>{host.event}</td></tr>)}</tbody></table>{shown.length === 0 && <PageState kind="empty" compact message={hosts.length === 0 ? "尚未接入服务器，请先在资产页添加服务器。" : "没有符合当前筛选条件的服务器。"} />}<div className="table-footer">共 {shown.length} 条 <span><button className="icon-button"><ChevronLeft size={16} /></button><button className="pager-current">1</button><button className="icon-button"><ChevronRight size={16} /></button></span></div></div>
      </div>
      <aside className="right-rail"><section className="rail-card"><div className="card-heading"><h2>未确认事件 <b>{incidents.length}</b></h2><button className="text-button" onClick={() => setActive("事件")}>查看更多</button></div>{incidents.slice(0, 5).map((incident) => <button className="incident-row" key={incident.id} onClick={() => onOpenIncident(incident)}><span><StatusDot status={incident.severity} /><strong>{incident.title}</strong><small>{incident.host} / {incident.ip} · {incident.started}</small></span><a>查看详情</a></button>)}{incidents.length === 0 && <PageState kind="empty" compact message="当前没有未确认事件。" />}</section><section className="rail-card"><div className="card-heading"><h2>监控链路</h2></div>{(ha?.failoverSupported ? [["主节点", isPrimary ? "活动" : "待命"], ["备节点", !isPrimary ? "活动" : "待命"]] : [["当前节点", "正常"], ["主备能力", "未启用"]]).concat([["中心端 API", "正常"]]).map(([name, state]) => <div className="health-row" key={name}><span>{name}</span><span><StatusDot status={state} /> {state}</span></div>)}</section><section className="rail-card trend-card"><div className="card-heading"><h2>趋势图（最近 24 小时）</h2></div><PageState kind="empty" compact message="中心端暂未提供总览聚合趋势。" /></section></aside>
    </section>
  </>;
}

function IncidentDrawer({ incident, onClose, onUpdate, onOpenHost }) {
  const [note, setNote] = useState("");
  if (!incident) return null;
  return <div className="drawer-backdrop"><aside className="incident-drawer"><div className="drawer-title"><div><Severity value={incident.severity} /><h2>{incident.title}</h2></div><button className="icon-button" onClick={onClose}><X /></button></div><section><h3>事件概览</h3><dl><dt>主机名</dt><dd><a onClick={() => onOpenHost({ id: incident.host, ip: incident.ip })}>{incident.host} ({incident.ip})</a></dd><dt>业务系统</dt><dd>数据库</dd><dt>事件类型</dt><dd>{incident.signal}</dd><dt>严重程度</dt><dd><Severity value={incident.severity} /></dd><dt>开始时间</dt><dd>2025-05-26 {incident.started}</dd><dt>持续时长</dt><dd>{incident.duration}</dd></dl></section><section><h3>关联信号</h3><div className="signal-box"><span>{incident.signal}<b className="red-text">{incident.value}</b></span><span>代理心跳<b className="green-text">正常（6 秒前）</b></span><span>ICMP 延迟<b className="green-text">15 ms</b></span></div></section><section><h3>事件时间线</h3><div className="timeline"><p><i className="red" />{incident.started} <span>触发告警：{incident.title}</span></p><p><i />{incident.started} <span>发送通知：数据库值班组（短信）</span></p><p><i />10:22:24 <span>事件创建</span></p></div></section><section><h3>备注</h3><textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="填写备注信息..." maxLength={200} /><small className="char-count">{note.length}/200</small></section><div className="drawer-actions"><button className="danger-button" onClick={() => onUpdate(incident.id, "确认")}>确认事件</button><button className="subtle-button" onClick={() => onUpdate(incident.id, "静默")}>临时静默</button><button className="subtle-button" onClick={() => onUpdate(incident.id, "维护")}>进入维护</button></div></aside></div>;
}

function AssetDetail({ host, onBack }) {
  const [tab, setTab] = useState("指标趋势");
  const [data, setData] = useState([]);
  const [metricsState, setMetricsState] = useState({ status: "loading", error: "" });
  useEffect(() => {
    if (!host?.id) return;
    setMetricsState({ status: "loading", error: "" });
    requestJson(`/api/hosts/${encodeURIComponent(host.id)}/metrics`).then((samples) => {
      setData(samples.map((sample, index) => ({ time: new Date(sample.collectedAt).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" }), cpu: sample.cpu, memory: sample.memory, disk: sample.disk, latency: sample.latency, index })));
      setMetricsState({ status: "ready", error: "" });
    }).catch((error) => setMetricsState({ status: "error", error: error.message }));
  }, [host?.id]);
  return <><div className="breadcrumb"><button onClick={onBack}>资产</button> / {host?.id}</div><section className="asset-header"><h1>{host?.id}</h1><span><StatusDot status={host?.status === "健康" ? "健康" : "严重"} /> {host?.status || "正常"}</span><dl><div><dt>IP</dt><dd>{host?.ip}</dd></div><div><dt>机房</dt><dd>{host?.room || "生产机房 A"}</dd></div><div><dt>类型</dt><dd>{host?.service || "数据库"}</dd></div><div><dt>所有者</dt><dd>数据库值班组</dd></div><div><dt>Agent 版本</dt><dd>待中心端接入</dd></div><div><dt>最后心跳</dt><dd>{host?.heartbeat || "-"}</dd></div></dl></section><div className="tabs">{["概览", "指标趋势", "检查项", "服务", "事件", "配置"].map((item) => <button key={item} className={tab === item ? "selected" : ""} onClick={() => setTab(item)}>{item}</button>)}<span /><button className="outline-button">近 24 小时</button><button className="outline-button">7 天</button></div><section className="asset-grid"><div>{metricsState.status === "loading" ? <PageState kind="loading" message="正在加载主机指标…" /> : metricsState.status === "error" ? <PageState kind="error" message={metricsState.error} /> : data.length === 0 ? <PageState kind="empty" message="该主机尚无指标样本。" /> : ["CPU 使用率 (%)", "内存使用率 (%)", "磁盘使用率 (%)", "网络延迟 (ms)"].map((name, index) => { const dataKey = index === 0 ? "cpu" : index === 1 ? "memory" : index === 2 ? "disk" : "latency"; return <section className="chart-panel" key={name}><h2>{name}<small>最新：{host?.[dataKey] == null ? "-" : `${host[dataKey]}${index === 3 ? " ms" : "%"}`}</small></h2><Suspense fallback={<PageState kind="loading" compact message="正在加载图表…" />}><MetricTrend data={data} dataKey={dataKey} stroke={index === 2 ? "#ef4444" : "#1463df"} /></Suspense></section>; })}</div><aside><section className="side-info"><h2>当前告警 <b>0</b></h2><p>详情接口暂未提供该资产关联事件。</p></section><section className="side-info"><h2>监控健康</h2><p>Agent 心跳<span><StatusDot status={host?.heartbeat === "失联" ? "严重" : "健康"} />{host?.heartbeat || "-"}</span></p></section><section className="side-info"><h2>资产信息</h2>{[["主机名", host?.id], ["IP 地址", host?.ip], ["机房", host?.room || "生产机房 A"], ["业务系统", host?.service || "-"], ["状态", host?.status || "未知"]].map(([key, value]) => <p key={key}>{key}<span>{value}</span></p>)}</section></aside></section></>;
}

function RulesPage() {
  const [editing, setEditing] = useState(null);
  const [enabled, setEnabled] = useState(rules.map(() => true));
  const toggleRule = (index) => { const next = !enabled[index]; setEnabled(enabled.map((value, itemIndex) => itemIndex === index ? next : value)); if (index < 2) requestJson(`/api/rules/${index + 1}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: next, warningThreshold: index === 0 ? 85 : 15, criticalThreshold: index === 0 ? 90 : 8 }) }).catch(() => {}); };
  return <><div className="page-title"><div><h1>告警规则与分组继承 <CircleHelp size={18} /></h1><p>告警规则可从服务器组继承，并可在单台服务器上单独覆盖阈值、级别或状态。</p></div></div><div className="rules-layout"><section><div className="filters"><select><option>规则状态：全部</option></select><select><option>严重级别：全部</option></select><select><option>服务器组：全部</option></select><label><Search size={16} /><input placeholder="搜索规则名称或检查项" /></label><button className="primary-button" onClick={() => setEditing(rules[2])}>新建规则</button></div><div className="table-wrap"><table><thead><tr><th>启用</th><th>规则名称</th><th>检查项</th><th>作用范围</th><th>阈值 / 持续时间</th><th>严重级别</th><th>继承关系</th><th>操作</th></tr></thead><tbody>{rules.map((rule, index) => <tr key={rule[0]}><td><button aria-label="切换规则" className={`toggle ${enabled[index] ? "on" : ""}`} onClick={() => toggleRule(index)}><i /></button></td><td>{rule[0]}</td><td>{rule[1]}</td><td>数据库服务器组</td><td>{rule[2]}</td><td><Severity value={rule[3]} /></td><td>组默认<br /><small>0 覆盖</small></td><td><button className="text-button" onClick={() => setEditing(rule)}>编辑</button> <button className="text-button">复制</button></td></tr>)}</tbody></table></div><section className="check-list"><h2>检查项</h2><table><thead><tr><th>检查项</th><th>类型</th><th>代理要求</th><th>说明</th><th>示例 / 端口</th></tr></thead><tbody>{[["ICMP", "可用性", "无代理", "通过 ICMP Echo 检查主机可达性与延迟。", "ping"], ["TCP 1433", "端口", "无代理", "检查 TCP 端口是否可连接。", "端口 1433"], ["HTTPS 证书", "SSL/TLS", "无代理", "检查证书有效期、颁发者与域名匹配。", "端口 443"], ["Windows 服务", "系统", "代理", "检查 Windows 服务运行状态。", "服务名"]].map((row) => <tr key={row[0]}>{row.map((cell) => <td key={cell}>{cell}</td>)}</tr>)}</tbody></table></section></section>{editing && <RuleDrawer rule={editing} onClose={() => setEditing(null)} />}</div></>;
}

function RuleDrawer({ rule, onClose }) { const [name, setName] = useState(rule[0]); const [critical, setCritical] = useState("8"); return <aside className="right-drawer"><div className="drawer-title"><h2>编辑规则 · {rule[0]}</h2><button className="icon-button" onClick={onClose}><X /></button></div><label>规则名称<input value={name} onChange={(e) => setName(e.target.value)} /></label><label>作用范围<select><option>服务器组默认</option><option>特定服务器</option></select></label><label>服务器组<select><option>数据库服务器组</option><option>生产服务器组</option></select></label><label>检查项<select><option>磁盘可用空间</option><option>CPU 使用率</option></select></label><h3>阈值设置</h3><div className="threshold"><Severity value="警告" /><span>&lt;</span><input type="number" defaultValue="15" /><span>%</span></div><div className="threshold"><Severity value="严重" /><span>&lt;</span><input type="number" value={critical} onChange={(e) => setCritical(e.target.value)} /><span>%</span></div><label>持续时间<select><option>连续 2 次 / 60 秒</option><option>连续 3 次 / 5 分钟</option></select></label><label>通知策略<select><option>严重事件发送短信</option><option>仅记录</option></select></label><button className="toggle on"><i /></button> <span>维护窗口内仅记录</span><div className="drawer-actions"><button className="subtle-button" onClick={onClose}>取消</button><button className="primary-button" onClick={onClose}>保存规则</button></div></aside>; }

function NotificationPage() {
  const [failed, setFailed] = useState(true); const [editing, setEditing] = useState(false);
  const policyRows = [["生产严重告警短信", "生产服务器组（23 台）", "严重", "一线运维值班组", "工作日 09:00–18:00", "立即 / 15分钟 / 60分钟", true], ["数据库磁盘告警", "数据库组", "重要", "DBA 值班组", "每天 00:00–24:00", "立即 / 30分钟 / 120分钟", true], ["非关键组仅面板记录", "非关键服务器组", "次要", "—", "每天 00:00–24:00", "—", false], ["维护窗口内静默", "全部服务器组", "警告", "—", "维护窗口内", "—", true]];
  const savePolicy = () => { requestJson("/api/notification-policies/1", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: true, repeatMinutes: 15 }) }).finally(() => setEditing(false)); };
  return <><div className="page-title"><div><h1>通知策略</h1><p>配置服务器分组、严重级别和短信重复提醒。</p></div></div><div className="rules-layout"><section><div className="table-wrap"><table><thead><tr><th>策略名称</th><th>适用服务器组</th><th>严重级别</th><th>通知对象</th><th>值班时间</th><th>首次/重复/升级</th><th>状态</th><th>操作</th></tr></thead><tbody>{policyRows.map((row) => <tr key={row[0]}>{row.slice(0, 6).map((value, index) => <td key={index}>{index === 2 ? <Severity value={value} /> : value}</td>)}<td><span className={row[6] ? "tag-enabled" : "tag-disabled"}>{row[6] ? "启用" : "停用"}</span></td><td><button className="text-button" onClick={() => setEditing(true)}>编辑</button></td></tr>)}</tbody></table></div></section><aside className="management-side"><section className="side-info"><h2>部署能力</h2><p>运行模式<span>单节点</span></p><p>主备切换<span className="muted">尚未实现</span></p><p>短信通道<span>待生产配置</span></p></section></aside></div>{editing && <NotificationDrawer failed={failed} setFailed={setFailed} onClose={() => setEditing(false)} onSave={savePolicy} />}</>;
}

function MaintenanceList() { return <section className="check-list"><h2>近期维护窗口 <button className="primary-button">新建维护窗口</button></h2><table><thead><tr><th>窗口名称</th><th>影响范围</th><th>时间范围</th><th>状态</th><th>创建人</th></tr></thead><tbody><tr><td>数据库补丁升级</td><td>数据库组</td><td>2025-05-15 10:00 ~ 12:00</td><td><span className="severity warning">进行中（仅记录）</span></td><td>admin</td></tr><tr><td>存储固件升级</td><td>存储设备组</td><td>2025-05-17 22:00 ~ 2025-05-18 02:00</td><td>计划中</td><td>ops</td></tr></tbody></table></section>; }
function UsersList() { return <section className="check-list"><h2>账号与角色</h2><table><thead><tr><th>账号</th><th>角色</th><th>最近登录</th><th>状态</th><th>操作</th></tr></thead><tbody>{[["admin", "管理员", "刚刚", "启用"], ["ops", "运维员", "今天 09:22", "启用"], ["viewer", "只读用户", "昨天 16:40", "启用"]].map((row) => <tr key={row[0]}>{row.map((v) => <td key={v}>{v}</td>)}<td><button className="text-button">编辑</button></td></tr>)}</tbody></table></section>; }
function Contacts() { return <section className="check-list"><h2>联系人组 <button className="primary-button">添加联系人</button></h2><table><thead><tr><th>组名</th><th>联系人</th><th>通知渠道</th><th>适用时间</th></tr></thead><tbody><tr><td>一线运维值班组</td><td>张工、李工</td><td>腾讯云短信</td><td>工作日 09:00–18:00</td></tr><tr><td>DBA 值班组</td><td>王工</td><td>腾讯云短信</td><td>每天 00:00–24:00</td></tr></tbody></table></section>; }
function NotificationDrawer({ failed, setFailed, onClose, onSave }) { return <aside className="right-drawer"><div className="drawer-title"><h2>编辑通知策略 · 生产严重告警短信</h2><button className="icon-button" onClick={onClose}><X /></button></div><label>策略名称<input defaultValue="生产严重告警短信" /></label><label>适用服务器组<select><option>生产服务器组（23 台）</option></select></label><h3>严重级别</h3><div className="severity-switch"><Severity value="严重" /><span>重要</span><span>警告</span><span>次要</span></div><label>通知渠道<select><option>腾讯云短信</option></select></label><label>通知对象<select><option>一线运维值班组</option></select></label><label>值班时间<select><option>工作日 09:00–18:00</option></select></label><div className="switch-lines">{["首次立即通知", "15 分钟后重复提醒（最多 3 次）", "60 分钟后升级至二线", "恢复时发送一次通知"].map((text) => <p key={text}><button className="toggle on"><i /></button>{text}</p>)}</div>{failed && <section className="sms-error"><h3><AlertTriangle size={16} />短信发送失败</h3><p>腾讯云短信接口返回错误：Code=InvalidParam</p><p>第 2 次重试将在 <b>3 分钟后</b>执行</p><button className="danger-button" onClick={() => setFailed(false)}>立即重试</button></section>}<div className="drawer-actions"><button className="primary-button" onClick={onSave}>保存</button><button className="subtle-button" onClick={onClose}>取消</button></div></aside>; }

function IncidentList({ incidents, onOpenIncident }) { return <><div className="page-title"><div><h1>事件管理</h1><p>查看、确认、静默和追踪所有运行事件。</p></div></div><div className="filters"><select><option>全部状态</option></select><select><option>全部严重级别</option></select><select><option>全部机房</option></select><label><Search size={16} /><input placeholder="搜索主机或事件" /></label><button className="subtle-button"><Filter size={16} />筛选</button></div><div className="table-wrap incident-table"><table><thead><tr><th>状态</th><th>严重级别</th><th>主机</th><th>事件类型</th><th>开始时间</th><th>持续时间</th><th>处置人</th><th>操作</th></tr></thead><tbody>{incidents.map((item) => <tr key={item.id}><td><StatusDot status={item.severity} />{item.state}</td><td><Severity value={item.severity} /></td><td><a>{item.host}</a><small>{item.ip}</small></td><td>{item.title}</td><td>{item.started}</td><td>{item.duration}</td><td>-</td><td><button className="text-button" onClick={() => onOpenIncident(item)}>处置</button></td></tr>)}</tbody></table></div></>;
}

function AssetsPage({ hosts, saveHost, deleteHost, openHost }) {
  const [query, setQuery] = useState(""); const [form, setForm] = useState(null); const [error, setError] = useState("");
  const shown = hosts.filter((host) => `${host.id} ${host.ip} ${host.room} ${host.service}`.toLowerCase().includes(query.toLowerCase()));
  const submit = async (event) => { event.preventDefault(); try { await saveHost(form); setForm(null); } catch (reason) { setError(reason.message); } };
  return <><div className="page-title"><div><h1>资产管理</h1><p>管理服务器信息、分组归属与监控接入状态。</p></div><button className="primary-button" onClick={() => { setError(""); setForm({ id: "", ip: "", room: "生产机房 A", service: "", isNew: true }); }}>添加服务器</button></div><div className="filters"><label><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索主机名、IP、机房或业务系统" /></label><button className="subtle-button" onClick={() => setQuery("")}>重置</button></div><div className="table-wrap"><table><thead><tr><th>状态</th><th>主机名 / IP</th><th>机房</th><th>业务系统</th><th>CPU</th><th>内存</th><th>磁盘</th><th>最后心跳</th><th>操作</th></tr></thead><tbody>{shown.map((host) => <tr key={host.id}><td><StatusDot status={host.status} /> {host.status}</td><td><a onClick={() => openHost(host)}>{host.id}</a><small>{host.ip}</small></td><td>{host.room}</td><td>{host.service}</td><td><MetricBar value={host.cpu} /></td><td><MetricBar value={host.memory} /></td><td><MetricBar value={host.disk} /></td><td>{host.heartbeat}</td><td><button className="text-button" onClick={() => openHost(host)}>详情</button><button className="text-button" onClick={() => { setError(""); setForm({ ...host, originalName: host.id }); }}>编辑</button><button className="text-button" style={{ color: "#d92d20" }} onClick={() => deleteHost(host)}>删除</button></td></tr>)}</tbody></table><div className="table-footer">共 {shown.length} 台服务器</div></div>{form && <aside className="right-drawer"><div className="drawer-title"><h2>{form.isNew ? "添加服务器" : `编辑服务器 · ${form.id}`}</h2><button className="icon-button" onClick={() => setForm(null)}><X /></button></div><form onSubmit={submit}><label>服务器名称<input autoFocus value={form.id} onChange={(event) => setForm({ ...form, id: event.target.value })} /></label><label>IP 地址<input value={form.ip} onChange={(event) => setForm({ ...form, ip: event.target.value })} /></label><label>机房<input value={form.room} onChange={(event) => setForm({ ...form, room: event.target.value })} /></label><label>业务系统<input value={form.service} onChange={(event) => setForm({ ...form, service: event.target.value })} /></label>{error && <p style={{ color: "#b42318", fontSize: 13 }}>{error}</p>}<div className="drawer-actions"><button className="primary-button">保存服务器</button><button type="button" className="subtle-button" onClick={() => setForm(null)}>取消</button></div></form></aside>}</>;
}

export function App() {
  const [session, setSession] = useState({ status: getAccessToken() ? "checking" : "anonymous", user: null }); const [active, setActive] = useState("总览"); const [hosts, setHosts] = useState([]); const [incidents, setIncidents] = useState([]); const [drawer, setDrawer] = useState(null); const [selectedHost, setSelectedHost] = useState(null); const [isPrimary, setIsPrimary] = useState(true); const [ha, setHa] = useState(null); const [dataState, setDataState] = useState({ status: "loading", error: "" });
  const loadDashboard = useCallback(async () => {
    setDataState({ status: "loading", error: "" });
    try {
      const dashboard = await getDashboard();
      setHosts(dashboard.hosts);
      setIncidents(dashboard.incidents);
      setIsPrimary(dashboard.isPrimary);
      setHa(dashboard.ha);
      setDataState({ status: "ready", error: "" });
    } catch (error) {
      setDataState({ status: "error", error: error.message });
    }
  }, []);
  useEffect(() => { if (session.status !== "checking") return; getCurrentUser().then((user) => setSession({ status: "authenticated", user })).catch(() => { clearAccessToken(); setSession({ status: "anonymous", user: null }); }); }, [session.status]);
  useEffect(() => { if (session.status === "authenticated") loadDashboard(); }, [loadDashboard, session.status]);
  const authenticate = async (username, password) => { await login(username, password); const user = await getCurrentUser(); setSession({ status: "authenticated", user }); };
  const logout = () => { clearAccessToken(); setSession({ status: "anonymous", user: null }); setHosts([]); setIncidents([]); setSelectedHost(null); setDrawer(null); };
  const openHost = (host) => { setSelectedHost({ ...hosts.find((item) => item.id === host.id), ...host }); setDrawer(null); };
  const updateIncident = async (id, action) => { const operation = action === "确认" ? "acknowledge" : action === "静默" ? "silence" : "maintenance"; try { await requestJson(`/api/incidents/${id}/${operation}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ note: "控制台处置" }) }); setIncidents((current) => current.filter((item) => item.id !== id)); setDrawer(null); } catch (error) { window.alert(error.message); } };
  const saveHost = async (host) => { const saved = await requestJson(host.originalName ? `/api/hosts/${encodeURIComponent(host.originalName)}` : "/api/hosts", { method: host.originalName ? "PUT" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: host.id, ip: host.ip, room: host.room, service: host.service }) }); const next = { ...saved, event: "-" }; setHosts((current) => host.originalName ? current.map((item) => item.id === host.originalName ? next : item) : [...current, next].sort((left, right) => left.id.localeCompare(right.id))); };
  const deleteHost = async (host) => { if (!window.confirm(`确定删除服务器 ${host.id} 吗？该操作会删除其指标样本。`)) return; try { await requestJson(`/api/hosts/${encodeURIComponent(host.id)}`, { method: "DELETE" }); setHosts((current) => current.filter((item) => item.id !== host.id)); } catch (error) { window.alert(error.message); } };
  let content = <Overview hosts={hosts} incidents={incidents} onOpenIncident={setDrawer} onOpenHost={openHost} setActive={setActive} dataState={dataState} onRetry={loadDashboard} isPrimary={isPrimary} ha={ha} />;
  if (selectedHost) content = <AssetDetail host={selectedHost} onBack={() => setSelectedHost(null)} />;
  else if (active === "事件") content = <IncidentList incidents={incidents} onOpenIncident={setDrawer} />;
  else if (active === "告警规则") content = <RulesPage />;
  else if (active === "通知") content = <NotificationPage />;
  else if (active === "资产") content = <AssetsPage hosts={hosts} saveHost={saveHost} deleteHost={deleteHost} openHost={openHost} />;
  if (session.status === "checking") return <PageState kind="loading" message="正在验证登录状态…" />;
  if (session.status !== "authenticated") return <LoginScreen onLogin={authenticate} />;
  return <AppShell active={active} setActive={(next) => { setSelectedHost(null); setActive(next); }} incidentCount={incidents.length} isPrimary={isPrimary} ha={ha} dataStatus={dataState.status} user={session.user} onLogout={logout}>{content}<IncidentDrawer incident={drawer} onClose={() => setDrawer(null)} onUpdate={updateIncident} onOpenHost={openHost} /></AppShell>;
}
