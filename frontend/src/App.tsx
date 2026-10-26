import { zodResolver } from "@hookform/resolvers/zod";
import {
  Activity, AlertCircle, ArrowRight, ArrowUpRight, BarChart3,
  Bell, Check, ChevronLeft, ChevronRight, Clock3, Download,
  FileClock, FileText, Filter, Fingerprint, FolderSearch,
  LayoutDashboard, ListFilter, LoaderCircle, LockKeyhole, LogOut, Menu, Moon,
  Plus, Search, Settings as SettingsIcon, Shield, ShieldAlert, ShieldCheck, Siren, Sun,
  Upload, UserRound, X,
} from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { FormEvent, useCallback, useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { z } from "zod";
import { api, ApiError, DEFAULT_PAGE_SIZE, getToken, LoginResponse, setToken } from "./api";

type JsonRecord = Record<string, unknown>;
type LoadState<T> = { data: T | null; loading: boolean; error: string | null; reload: () => void };

function useRemote<T>(load: () => Promise<T>, dependencies: unknown[] = []): LoadState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision((current) => current + 1), []);
  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    load().then((result) => {
      if (active) setData(result);
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : "Something went wrong.");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
    // The caller controls the request identity through dependencies.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revision, ...dependencies]);
  return { data, loading, error, reload };
}

const navigation = [
  { label: "Workspace", links: [
    { to: "/", name: "Overview", icon: LayoutDashboard },
    { to: "/incidents", name: "Incidents", icon: ShieldAlert },
    { to: "/imported-alerts", name: "Imported alerts", icon: Siren },
    { to: "/evidence", name: "Evidence", icon: FolderSearch },
    { to: "/indicators", name: "Indicators", icon: Fingerprint },
  ] },
  { label: "Intelligence", links: [
    { to: "/analytics", name: "Analytics", icon: BarChart3 },
    { to: "/reports", name: "Reports", icon: FileText },
    { to: "/audit", name: "Audit log", icon: FileClock },
  ] },
];

function App() {
  const [authenticated, setAuthenticated] = useState(Boolean(getToken()));
  const [currentUser, setCurrentUser] = useState<{ username?: string; role?: string }>(() => {
    try { return asRecord(JSON.parse(localStorage.getItem("cybershield.user") ?? "{}")); }
    catch { return {}; }
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [dark, setDark] = useState(localStorage.getItem("cybershield.theme") !== "light");
  const [toast, setToast] = useState("");
  const location = useLocation();
  useEffect(() => { setMobileOpen(false); }, [location.pathname]);
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("cybershield.theme", dark ? "dark" : "light");
  }, [dark]);
  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3500);
    return () => window.clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    if (!authenticated) return;
    api.me().then((user) => {
      const safeUser = asRecord(user);
      setCurrentUser(safeUser);
      localStorage.setItem("cybershield.user", JSON.stringify(safeUser));
    }).catch((error: unknown) => {
      if (error instanceof ApiError && error.status === 401) {
        setToken(null);
        localStorage.removeItem("cybershield.user");
        setAuthenticated(false);
      } else if (error instanceof Error) setToast(error.message);
    });
  }, [authenticated]);
  const logout = async () => {
    try { await api.logout(); }
    catch (error) { setToast(error instanceof Error ? `Signed out locally; server logout failed: ${error.message}` : "Signed out locally."); }
    finally { setToken(null); localStorage.removeItem("cybershield.user"); setCurrentUser({}); setAuthenticated(false); }
  };

  return (
    <div className="app-shell">
      {authenticated ? (
        <>
          <button className={`drawer-scrim ${mobileOpen ? "visible" : ""}`} aria-label="Close navigation" onClick={() => setMobileOpen(false)} />
          <aside className={`sidebar ${mobileOpen ? "open" : ""}`} aria-label="Main navigation">
            <div className="brand"><span className="brand-mark"><Shield size={20} /></span><span>CYBER<span className="brand-accent">SHIELD</span><small>SECURITY OPERATIONS</small></span><button className="icon-button drawer-close" aria-label="Close menu" onClick={() => setMobileOpen(false)}><X size={19} /></button></div>
            <div className="workspace-selector"><span className="workspace-icon"><Shield size={16} /></span><span><b>Organization workspace</b><small>Security operations</small></span></div>
            <nav className="nav-groups">
              {navigation.map((group) => <div className="nav-group" key={group.label}><p className="nav-heading">{group.label}</p>{group.links.map(({ to, name, icon: Icon }) => <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}><Icon size={17} strokeWidth={1.8} /><span>{name}</span></NavLink>)}</div>)}
            </nav>
            <div className="sidebar-bottom">
              <NavLink to="/settings" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}><SettingsIcon size={17} /><span>Settings</span></NavLink>
              <button className="profile-card" onClick={logout}><span className="avatar"><UserRound size={15} /></span><span><b>{text(currentUser.username, "Authenticated user")}</b><small>{text(currentUser.role, "Authorized account")}</small></span><LogOut size={16} aria-label="Sign out" /></button>
            </div>
          </aside>
          <main className="main-area">
            <header className="topbar">
              <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={21} /></button>
              <div className="breadcrumb"><span>CyberShield Demo Environment</span><ChevronRight size={14} /><b>{pageTitle(location.pathname)}</b></div>
              <div className="topbar-actions"><button className="icon-button theme-toggle" aria-label={`Switch to ${dark ? "light" : "dark"} theme`} onClick={() => setDark(!dark)}>{dark ? <Sun size={18} /> : <Moon size={18} />}</button><Link className="icon-button notification-button" aria-label="Open audit log" to="/audit"><Bell size={18} /></Link><span className="topbar-divider" /><span className="avatar small-avatar"><UserRound size={14} /></span></div>
            </header>
            <div className="page-container">
              <Routes>
                <Route path="/" element={<Dashboard toast={setToast} />} />
                <Route path="/incidents" element={<Incidents onImported={setToast} />} />
                <Route path="/imported-alerts" element={<ImportedAlerts onPromoted={setToast} />} />
                <Route path="/incidents/new" element={<NewIncident onCreated={setToast} />} />
                <Route path="/incidents/:id" element={<IncidentDetail onUpdated={setToast} />} />
                <Route path="/evidence" element={<ResourcePage type="evidence" />} />
                <Route path="/indicators" element={<ResourcePage type="indicators" />} />
                <Route path="/analytics" element={<Analytics />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/audit" element={<ResourcePage type="audit" />} />
                <Route path="/settings" element={<Settings onSaved={setToast} />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </div>
          </main>
          {toast && <div role="status" className="toast"><Check size={17} />{toast}</div>}
        </>
      ) : <Login onLogin={(user) => { setCurrentUser(user); localStorage.setItem("cybershield.user", JSON.stringify(user)); setAuthenticated(true); }} />}
    </div>
  );
}

function pageTitle(path: string) {
  if (path.startsWith("/incidents/")) return path.includes("/new") ? "New incident" : "Incident detail";
  return navigation.flatMap((group) => group.links).find((item) => item.to === path)?.name
    ?? (path === "/settings" ? "Settings" : "Security operations");
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: React.ReactNode }) {
  return <div className="page-heading"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{description && <p className="page-description">{description}</p>}</div>{action && <div className="heading-action">{action}</div>}</div>;
}

function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="state-card error-state"><span className="state-icon danger"><AlertCircle size={20} /></span><div><b>Could not load data</b><p>{message}</p>{retry && <button className="text-button" onClick={retry}>Try again</button>}</div></div>;
}

function LoadingState({ label = "Loading data…" }: { label?: string }) {
  return <div className="state-card"><LoaderCircle className="spin" size={19} /><span>{label}</span></div>;
}

function EmptyState({ title, detail, action }: { title: string; detail: string; action?: React.ReactNode }) {
  return <div className="empty-state"><span className="empty-icon"><FolderSearch size={22} /></span><b>{title}</b><p>{detail}</p>{action}</div>;
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}
function unwrapRecord(value: unknown): JsonRecord {
  const record = asRecord(value);
  return asRecord(valueAt(record, "data") ?? record);
}
function text(value: unknown, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
function valueAt(data: JsonRecord, ...keys: string[]) {
  for (const key of keys) if (data[key] !== undefined && data[key] !== null) return data[key];
  return undefined;
}
function readField(data: JsonRecord, key: string) {
  const snakeCase = key.replace(/[A-Z]/g, (character) => `_${character.toLowerCase()}`);
  return valueAt(data, key, snakeCase);
}
function formatDate(value: unknown) {
  if (!value) return "—";
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
function getArray(payload: unknown): unknown[] {
  if (Array.isArray(payload)) return payload;
  const record = asRecord(payload);
  for (const key of ["data", "items", "results", "incidents", "evidence", "indicators", "reports", "logs"]) {
    if (Array.isArray(record[key])) return record[key] as unknown[];
  }
  return [];
}

function Dashboard({ toast }: { toast: (message: string) => void }) {
  const state = useRemote(api.dashboard);
  const recentState = useRemote(() => api.incidents({ page: 1, pageSize: 5 }));
  const [query, setQuery] = useState("");
  const data = unwrapRecord(state.data);
  const severityCounts = asRecord(data.by_severity);
  const statusCounts = asRecord(data.by_status);
  const total = Number(data.total_incidents ?? 0);
  const open = Number(data.open_incidents ?? 0);
  const criticalHigh = Number(severityCounts.critical ?? 0) + Number(severityCounts.high ?? 0);
  const investigating = Number(statusCounts.investigating ?? 0);
  const resolved = Number(statusCounts.resolved ?? 0) + Number(statusCounts.closed ?? 0);
  const incidents = getArray(recentState.data);
  const metrics = [
    { label: "Total incidents", value: total, icon: ShieldCheck, tone: "blue", to: "/incidents" },
    { label: "Open incidents", value: open, icon: ShieldAlert, tone: "red", to: "/incidents?status=new" },
    { label: "Critical & high", value: criticalHigh, icon: Siren, tone: "amber", to: "/incidents?severity=high" },
    { label: "Under investigation", value: investigating, icon: Activity, tone: "amber", to: "/incidents?status=investigating" },
    { label: "Resolved", value: resolved, icon: ShieldCheck, tone: "green", to: "/incidents?status=resolved" },
    { label: "Evidence records", value: Number(data.evidence_count ?? 0), icon: FolderSearch, tone: "blue", to: "/evidence" },
    { label: "Mean time to resolve", value: "Insufficient data", icon: Clock3, tone: "green", to: "/analytics" },
  ];
  const filtered = incidents.filter((raw) => JSON.stringify(raw).toLowerCase().includes(query.toLowerCase()));
  const severityData = Object.entries(severityCounts).map(([severity, count]) => ({ severity, count }));
  const chart = Object.entries(asRecord(data.by_status)).map(([status, count]) => ({ status, count }));
  return <div className="page-content">
    <PageHeading eyebrow={new Intl.DateTimeFormat(undefined, { weekday: "long", month: "long", day: "numeric", year: "numeric" }).format(new Date()).toUpperCase()} title="Security operations overview" description="Current operational metrics and incident activity from your API." action={<button className="button secondary" onClick={() => { state.reload(); toast("Dashboard refresh requested"); }}><Activity size={16} /> Refresh</button>} />
    {state.loading ? <LoadingState label="Loading your security overview…" /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : <div className="dashboard-content">
      <div className="metric-grid">{metrics.map(({ label, value, icon: Icon, tone, to }) => <Link to={to} className="metric-card" key={label}><div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon size={17} /></span></div><div className="metric-value">{text(value)}</div><div className="metric-foot"><span>Database-derived</span></div></Link>)}</div>
      <div className="dashboard-grid"><section className="panel chart-panel"><div className="panel-header"><div><h2>Incident status</h2><p>Current persisted incident records</p></div></div>
        {chart.length ? <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chart} margin={{ top: 8, right: 10, left: -18, bottom: 0 }}><CartesianGrid strokeDasharray="4 5" stroke="var(--border)" vertical={false} /><XAxis dataKey="status" tick={{ fill: "var(--muted)", fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 9, color: "var(--text)" }} /><Area type="monotone" dataKey="count" stroke="#36d6a5" strokeWidth={2} fill="#36d6a522" /></AreaChart></ResponsiveContainer></div> : <EmptyState title="No status data" detail="Incident status data will appear after cases are recorded." />}
      </section><section className="panel severity-panel"><div className="panel-header"><div><h2>Severity breakdown</h2><p>All persisted incidents</p></div></div><SeverityBreakdown data={severityData} /></section></div>
      <section className="panel table-panel"><div className="panel-header"><div><h2>Recent incidents</h2><p>Latest activity from your response queue</p></div><Link className="text-link" to="/incidents">View all <ArrowRight size={14} /></Link></div><div className="table-tools"><label className="search-box"><Search size={15} /><input placeholder="Search incidents…" value={query} onChange={(event) => setQuery(event.target.value)} /></label><button className="button secondary compact" onClick={() => setQuery("")} disabled={!query}><Filter size={15} /> Clear search</button></div>
        {recentState.loading ? <LoadingState label="Loading recent incidents…" /> : recentState.error ? <ErrorState message={recentState.error} retry={recentState.reload} /> : incidents.length ? <IncidentTable rows={filtered} /> : <EmptyState title="No recent incidents" detail="Incident activity will appear here when cases are recorded." action={<Link className="button secondary compact" to="/incidents">Open incident queue</Link>} />}</section>
    </div>}
  </div>;
}

function SeverityBreakdown({ data }: { data: unknown[] }) {
  const rows = data.map(asRecord).map((record) => ({
    name: text(valueAt(record, "severity", "name"), "Unknown"),
    value: Number(valueAt(record, "count", "value")),
  })).filter((record) => Number.isFinite(record.value));
  const colors = ["#f36b74", "#f0ac55", "#6ba8ff", "#36d6a5"];
  return rows.length ? <div className="severity-layout"><div className="severity-chart"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={rows} dataKey="value" nameKey="name" innerRadius="67%" outerRadius="92%" paddingAngle={3} stroke="none">{rows.map((entry, index) => <Cell key={entry.name} fill={colors[index % colors.length]} />)}</Pie><Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 8, color: "var(--text)" }} /></PieChart></ResponsiveContainer></div><div className="severity-legend">{rows.map((row, index) => <div key={`${row.name}-${index}`}><span className="legend-dot" style={{ background: colors[index % colors.length] }} />{row.name}<b>{row.value}</b></div>)}</div></div> : <EmptyState title="No severity data" detail="Severity metrics will be shown here when available." />;
}

function IncidentTable({ rows }: { rows: unknown[] }) {
  return <div className="table-scroll"><table><thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Assigned to</th><th>Updated</th><th /></tr></thead><tbody>{rows.map((raw, index) => {
    const row = asRecord(raw);
    const id = text(valueAt(row, "id", "incidentId", "incident_id"), String(index));
    return <tr key={id}><td><Link className="incident-cell" to={`/incidents/${encodeURIComponent(id)}`}><span className="incident-id">{text(valueAt(row, "reference", "number", "incidentNumber", "incident_number"), `INC-${id}`)}</span><b>{text(valueAt(row, "title", "name"))}</b></Link></td><td><Severity value={text(row.severity, "Unknown")} /></td><td><Status value={text(valueAt(row, "status", "state"), "Unknown")} /></td><td>{text(valueAt(row, "assignee", "assignedTo", "assigned_to"))}</td><td>{formatDate(valueAt(row, "updatedAt", "updated_at", "createdAt", "created_at"))}</td><td><Link aria-label={`View incident ${id}`} className="row-action" to={`/incidents/${encodeURIComponent(id)}`}><ChevronRight size={16} /></Link></td></tr>;
  })}</tbody></table></div>;
}

function Severity({ value }: { value: string }) {
  const kind = value.toLowerCase();
  return <span className={`severity-tag ${kind}`}>{value}</span>;
}
function Status({ value }: { value: string }) {
  const kind = value.toLowerCase().replaceAll(" ", "-");
  return <span className={`status-tag ${kind}`}><i />{value}</span>;
}

function Incidents({ onImported }: { onImported: (message: string) => void }) {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const filter = searchParams.get("status") ?? "All";
  const severityFilter = searchParams.get("severity") ?? "";
  const categoryFilter = searchParams.get("category") ?? "";
  const assigneeFilter = searchParams.get("assignee") ?? "";
  const createdFrom = searchParams.get("created_from") ?? "";
  const createdTo = searchParams.get("created_to") ?? "";
  const sortByParam = searchParams.get("sort_by") ?? "updated_at";
  const sortBy = (["created_at", "severity", "updated_at"] as const).includes(sortByParam as "created_at" | "severity" | "updated_at")
    ? sortByParam as "created_at" | "severity" | "updated_at"
    : "updated_at";
  const sortOrderParam = searchParams.get("sort_order") ?? "desc";
  const sortOrder = sortOrderParam === "asc" ? "asc" : "desc";
  const [query, setQuery] = useState("");
  const updateParam = (key: string, value: string) => {
    setPage(1);
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next);
  };
  const state = useRemote(() => api.incidents({
    page,
    pageSize: DEFAULT_PAGE_SIZE,
    status: filter === "All" ? undefined : filter,
    severity: severityFilter || undefined,
    category: categoryFilter || undefined,
    assignee: assigneeFilter || undefined,
    search: query || undefined,
    createdFrom: createdFrom || undefined,
    createdTo: createdTo || undefined,
    sortBy,
    sortOrder,
  }), [page, filter, severityFilter, categoryFilter, assigneeFilter, createdFrom, createdTo, sortBy, sortOrder, query]);
  const items = getArray(state.data);
  const pageInfo = asRecord(state.data);
  const total = Number(pageInfo.total ?? 0);
  const currentPage = Number(pageInfo.page ?? page);
  const pageSize = Number(pageInfo.page_size ?? DEFAULT_PAGE_SIZE);
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const filtered = items;
  return <div className="page-content"><PageHeading eyebrow="RESPONSE QUEUE" title="Incidents" description="Triage, investigate, and resolve security incidents." action={<><AlertImport onImported={() => { state.reload(); onImported("Alert import completed"); navigate("/imported-alerts"); }} /><Link className="button secondary" to="/imported-alerts"><Siren size={16} /> Review imported alerts</Link><Link className="button primary" to="/incidents/new"><Plus size={16} /> New incident</Link></>} />
    <div className="filter-tabs" role="group" aria-label="Filter incidents">{["All", "new", "triaged", "investigating", "containment", "resolved", "closed"].map((item) => <button key={item} className={filter === item ? "selected" : ""} onClick={() => { setPage(1); const next = new URLSearchParams(searchParams); if (item === "All") next.delete("status"); else next.set("status", item); setSearchParams(next); }}>{item === "All" ? item : item[0].toUpperCase() + item.slice(1)}</button>)}</div>
    <section className="panel table-panel"><div className="table-tools"><label className="search-box"><Search size={15} /><input aria-label="Search incidents" placeholder="Search by title, ID, or assignee…" value={query} onChange={(event) => { setPage(1); setQuery(event.target.value); }} /></label>
      <label className="compact-filter"><span>Severity</span><select aria-label="Filter severity" value={severityFilter} onChange={(event) => { setPage(1); const next = new URLSearchParams(searchParams); if (event.target.value) next.set("severity", event.target.value); else next.delete("severity"); setSearchParams(next); }}><option value="">All</option>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
      <label className="compact-filter"><span>Category</span><input aria-label="Filter category" value={categoryFilter} onChange={(event) => { setPage(1); const next = new URLSearchParams(searchParams); if (event.target.value) next.set("category", event.target.value); else next.delete("category"); setSearchParams(next); }} placeholder="All" /></label>
      <label className="compact-filter"><span>Analyst</span><input aria-label="Filter analyst" value={assigneeFilter} onChange={(event) => { setPage(1); const next = new URLSearchParams(searchParams); if (event.target.value) next.set("assignee", event.target.value); else next.delete("assignee"); setSearchParams(next); }} placeholder="All" /></label>
      <label className="compact-filter"><span>Created from</span><input aria-label="Created from" type="date" value={createdFrom} onChange={(event) => updateParam("created_from", event.target.value)} /></label>
      <label className="compact-filter"><span>Created to</span><input aria-label="Created to" type="date" value={createdTo} onChange={(event) => updateParam("created_to", event.target.value)} /></label>
      <label className="compact-filter"><span>Sort by</span><select aria-label="Sort by" value={sortBy} onChange={(event) => updateParam("sort_by", event.target.value)}><option value="created_at">Created date</option><option value="severity">Severity</option><option value="updated_at">Last updated</option></select></label>
      <label className="compact-filter"><span>Order</span><select aria-label="Sort order" value={sortOrder} onChange={(event) => updateParam("sort_order", event.target.value)}><option value="desc">Newest first</option><option value="asc">Oldest first</option></select></label>
      <button className="button secondary compact" onClick={() => { setPage(1); setQuery(""); setSearchParams({}); }}><ListFilter size={15} /> Reset</button></div>
      {state.loading ? <LoadingState label="Loading incidents…" /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : filtered.length ? <><IncidentTable rows={filtered} />{total > pageSize && <div className="pagination"><span>Showing {(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, total)} of {total}</span><div><button className="button secondary compact" onClick={() => setPage((value) => Math.max(1, value - 1))} disabled={currentPage <= 1}><ChevronLeft size={14} /> Previous</button><span>Page {currentPage} of {pageCount}</span><button className="button secondary compact" onClick={() => setPage((value) => Math.min(pageCount, value + 1))} disabled={currentPage >= pageCount}>Next <ChevronRight size={14} /></button></div></div>}</> : <EmptyState title={items.length ? "No matching incidents" : "No incidents yet"} detail={items.length ? "Try changing your filters or search terms." : "Create an incident to start an investigation."} action={<Link className="button primary compact" to="/incidents/new"><Plus size={15} /> New incident</Link>} />}
    </section>
  </div>;
}

function AlertImport({ onImported }: { onImported: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async (file?: File) => {
    if (!file) return;
    setBusy(true);
    setError("");
    const form = new FormData();
    form.append("file", file);
    try {
      await api.importAlerts(form);
      onImported();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not import alerts.");
    } finally {
      setBusy(false);
    }
  };
  return <div className="import-alerts"><input className="file-input-hidden" id="alert-import-file" type="file" aria-label="Select alerts file to import" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; void submit(file); event.target.value = ""; }} /><button className="button secondary" onClick={() => document.getElementById("alert-import-file")?.click()} disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <Upload size={16} />} Import alerts</button>{error && <span className="inline-error import-error" role="alert"><AlertCircle size={15} />{error}</span>}</div>;
}

function ImportedAlerts({ onPromoted }: { onPromoted: (message: string) => void }) {
  const [reviewStatus, setReviewStatus] = useState<"pending" | "promoted">("pending");
  const state = useRemote(() => api.importedAlerts(reviewStatus), [reviewStatus]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState("");
  const alerts = getArray(state.data);

  const promote = async (id: string) => {
    if (!window.confirm("Promote this imported alert into a confirmed incident? This action is recorded in the audit log.")) return;
    setBusyId(id);
    setActionError("");
    try {
      await api.promoteImportedAlert(id);
      state.reload();
      onPromoted(`Alert ${id} promoted to an incident`);
    } catch (reason) {
      setActionError(reason instanceof Error ? reason.message : "Could not promote imported alert.");
    } finally {
      setBusyId(null);
    }
  };

  return <div className="page-content">
    <PageHeading eyebrow="INGESTION REVIEW" title="Imported alerts" description="Review source alerts from the import queue and promote verified alerts into incidents." action={<AlertImport onImported={state.reload} />} />
    {actionError && <div className="inline-error" role="alert"><AlertCircle size={16} />{actionError}</div>}
    <section className="panel table-panel">
      <div className="panel-header"><div><h2>Alert review queue</h2><p>Imported records stay separate from incidents until promoted.</p></div><div className="heading-action"><label className="compact-filter"><span>Review status</span><select aria-label="Alert review status" value={reviewStatus} onChange={(event) => setReviewStatus(event.target.value as "pending" | "promoted")}><option value="pending">Pending</option><option value="promoted">Promoted</option></select></label><button className="button secondary compact" onClick={state.reload}><Activity size={14} /> Refresh queue</button></div></div>
      {state.loading ? <LoadingState label="Loading imported alerts…" /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : alerts.length ? <div className="table-scroll"><table><thead><tr><th>Source ID</th><th>Alert</th><th>Source</th><th>Received</th><th>Status</th><th>Action</th></tr></thead><tbody>{alerts.map((raw, index) => {
        const alert = asRecord(raw);
        const id = text(alert.id, String(index));
        const sourceId = text(valueAt(alert, "source_id", "sourceId"), id);
        const status = text(valueAt(alert, "review_status", "status"), "pending");
        const promoted = status.toLowerCase() === "promoted";
        const displayStatus = promoted ? "Promoted" : status;
        return <tr key={id}><td><code className="hash-cell">{sourceId}</code></td><td><b>{text(valueAt(alert, "title", "name", "message"))}</b></td><td>{text(valueAt(alert, "source_system", "sourceSystem", "source"))}</td><td>{formatDate(valueAt(alert, "source_timestamp", "sourceTimestamp", "imported_at", "importedAt"))}</td><td><Status value={displayStatus} /></td><td>{promoted ? <span className="muted-copy inline-copy">Promoted</span> : <button className="button primary compact" disabled={busyId !== null} onClick={() => void promote(id)}>{busyId === id ? <LoaderCircle size={14} className="spin" /> : <ArrowUpRight size={14} />} Promote to incident</button>}</td></tr>;
      })}</tbody></table></div> : <EmptyState title="No imported alerts" detail="Import an alerts file to populate this review queue. No sample alerts are shown." action={<AlertImport onImported={state.reload} />} />}
    </section>
  </div>;
}

const incidentSchema = z.object({
  title: z.string().trim().min(3, "Title must be at least 3 characters."),
  description: z.string().trim().min(5, "Add a short description."),
  severity: z.enum(["critical", "high", "medium", "low"]),
  category: z.string().min(1, "Choose a category."),
  assignee: z.string().trim().max(80).optional(),
  reporter: z.string().trim().max(120).optional(),
  affected_asset: z.string().trim().max(200).optional(),
  source_ip: z.string().trim().max(45).optional(),
  destination_ip: z.string().trim().max(45).optional(),
  detection_source: z.string().trim().max(200).optional(),
});
type IncidentInput = z.infer<typeof incidentSchema>;

function NewIncident({ onCreated }: { onCreated: (message: string) => void }) {
  const navigate = useNavigate();
  const [apiError, setApiError] = useState("");
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<IncidentInput>({
    resolver: zodResolver(incidentSchema), defaultValues: { severity: "medium", category: "Malware", assignee: "", reporter: "", affected_asset: "", source_ip: "", destination_ip: "", detection_source: "" },
  });
  const submit = async (values: IncidentInput) => {
    setApiError("");
    try {
      const created = asRecord(await api.createIncident({ ...values, status: "new" }));
      onCreated("Incident created successfully");
      const id = valueAt(created, "id", "incidentId", "incident_id");
      navigate(id ? `/incidents/${encodeURIComponent(String(id))}` : "/incidents");
    } catch (error) { setApiError(error instanceof Error ? error.message : "Unable to create incident."); }
  };
  return <div className="page-content"><PageHeading eyebrow="RESPONSE QUEUE" title="Create incident" description="Capture the initial details to open an investigation." />
    <form className="form-card" onSubmit={handleSubmit(submit)}><div className="form-section-title"><span className="form-icon"><Siren size={18} /></span><div><h2>Incident details</h2><p>Fields marked with * are required.</p></div></div>
      <label className="field"><span>Incident title <i>*</i></span><input {...register("title")} placeholder="e.g. Suspicious login activity detected" aria-invalid={Boolean(errors.title)} />{errors.title && <small className="field-error">{errors.title.message}</small>}</label>
      <label className="field"><span>Description <i>*</i></span><textarea {...register("description")} rows={4} placeholder="Describe what happened, affected systems, and initial observations…" aria-invalid={Boolean(errors.description)} />{errors.description && <small className="field-error">{errors.description.message}</small>}</label>
      <div className="field-row"><label className="field"><span>Severity <i>*</i></span><select {...register("severity")}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>{errors.severity && <small className="field-error">{errors.severity.message}</small>}</label>
        <label className="field"><span>Category <i>*</i></span><select {...register("category")}><option>Malware</option><option>Phishing</option><option>Unauthorized access</option><option>Data exposure</option><option>Vulnerability</option><option>Other</option></select>{errors.category && <small className="field-error">{errors.category.message}</small>}</label></div>
      <div className="field-row"><label className="field"><span>Assigned analyst</span><input {...register("assignee")} placeholder="Analyst username" /></label><label className="field"><span>Reporter</span><input {...register("reporter")} /></label><label className="field"><span>Affected asset</span><input {...register("affected_asset")} placeholder="Hostname or asset identifier" /></label></div>
      <div className="field-row"><label className="field"><span>Source IP</span><input {...register("source_ip")} placeholder="Validated by the API" /></label><label className="field"><span>Destination IP</span><input {...register("destination_ip")} placeholder="Validated by the API" /></label><label className="field"><span>Detection source</span><input {...register("detection_source")} /></label></div>
      {apiError && <div className="inline-error" role="alert"><AlertCircle size={16} />{apiError}</div>}
      <div className="form-actions"><Link className="button secondary" to="/incidents">Cancel</Link><button className="button primary" disabled={isSubmitting}>{isSubmitting ? <LoaderCircle size={16} className="spin" /> : <Plus size={16} />} Create incident</button></div>
    </form>
  </div>;
}

function IncidentDetail({ onUpdated }: { onUpdated: (message: string) => void }) {
  const { id = "" } = useParams();
  const state = useRemote(() => api.incident(id), [id]);
  const timelineState = useRemote(() => api.timeline(id), [id]);
  const evidenceState = useRemote(() => api.evidence(id), [id]);
  const indicatorState = useRemote(() => api.indicators(id), [id]);
  const [event, setEvent] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const incident = unwrapRecord(state.data);
  const timeline = getArray(timelineState.data);
  const addEvent = async (eventObject: FormEvent) => {
    eventObject.preventDefault();
    if (!event.trim()) return;
    setBusy(true); setActionError("");
    try { await api.addTimelineEvent(id, { event_type: "analyst_note", description: event.trim() }); setEvent(""); timelineState.reload(); onUpdated("Investigation note added"); }
    catch (error) { setActionError(error instanceof Error ? error.message : "Could not add note."); }
    finally { setBusy(false); }
  };
  const resolve = async () => {
    if (!window.confirm("Resolve this incident? The status change will be recorded in the incident history.")) return;
    setBusy(true); setActionError("");
    try { await api.updateIncident(id, { status: "resolved" }); state.reload(); onUpdated("Incident status updated"); }
    catch (error) { setActionError(error instanceof Error ? error.message : "Could not update incident."); }
    finally { setBusy(false); }
  };
  return <div className="page-content">
    {state.loading ? <LoadingState label="Loading incident…" /> : state.error ? <><Link className="back-link" to="/incidents"><ChevronLeft size={15} /> Back to incidents</Link><ErrorState message={state.error} retry={state.reload} /></> : <>
      <Link className="back-link" to="/incidents"><ChevronLeft size={15} /> Back to incidents</Link>
      <PageHeading eyebrow={text(valueAt(incident, "reference", "number"), `INC-${id}`)} title={text(valueAt(incident, "title", "name"))} description={text(incident.description)} action={<button className="button secondary" onClick={resolve} disabled={busy || incident.status === "resolved" || incident.status === "closed"}><Check size={16} /> Mark resolved</button>} />
      {incident.simulated === true && <div className="simulated-banner" role="note"><Shield size={16} /> SIMULATED DATA — educational synthetic incident, not a real event</div>}
      <div className="detail-meta"><Severity value={text(incident.severity, "Unknown")} /><Status value={text(valueAt(incident, "status", "state"), "Unknown")} /><span><UserRound size={15} /> {text(valueAt(incident, "assignee", "assignedTo", "assigned_to"))}</span><span><Clock3 size={15} /> Opened {formatDate(valueAt(incident, "createdAt", "created_at"))}</span></div>
      {actionError && <div className="inline-error" role="alert"><AlertCircle size={16} />{actionError}</div>}
      <div className="detail-grid"><section className="panel detail-panel"><div className="panel-header"><div><h2>Investigation timeline</h2><p>Chronological response activity and analyst notes</p></div><span className="tiny-count">{timeline.length} events</span></div>
        {timelineState.loading ? <LoadingState label="Loading investigation timeline…" /> : timelineState.error ? <ErrorState message={timelineState.error} retry={timelineState.reload} /> : timeline.length ? <ol className="timeline">{timeline.map((raw, index) => { const item = asRecord(raw); return <li key={text(valueAt(item, "id"), String(index))}><span className="timeline-marker"><Activity size={14} /></span><div><div className="timeline-head"><b>{text(valueAt(item, "actor", "user", "event_type"), "Investigation update")}</b><time>{formatDate(valueAt(item, "occurred_at", "timestamp", "createdAt", "created_at"))}</time></div><p>{text(valueAt(item, "description", "message", "action"))}</p></div></li>; })}</ol> : <EmptyState title="No timeline events" detail="Add the initial observation or response step to begin documenting this investigation." />}
        <form className="timeline-form" onSubmit={addEvent}><label className="sr-only" htmlFor="timeline-note">Add an investigation note</label><input id="timeline-note" placeholder="Add an investigation note…" value={event} onChange={(e) => setEvent(e.target.value)} /><button className="button primary compact" disabled={busy || !event.trim()}><Plus size={15} /> Add note</button></form>
      </section>
      <aside className="detail-aside"><section className="panel detail-panel"><div className="panel-header"><div><h2>Incident metadata</h2><p>Core incident properties</p></div></div><dl className="metadata-list">{[["Category", incident.category], ["Priority", incident.priority], ["Reporter", incident.reporter], ["Assigned analyst", incident.assignee], ["Affected asset", incident.affected_asset], ["Source IP", incident.source_ip], ["Destination IP", incident.destination_ip], ["Detection source", incident.detection_source], ["Updated", formatDate(incident.updated_at)]].map(([key, value]) => <div key={String(key)}><dt>{text(key)}</dt><dd>{text(value)}</dd></div>)}</dl></section>
        <IncidentEdit incident={incident} onSaved={() => { state.reload(); onUpdated("Incident details updated"); }} />
        <ResourceSubsection title="Related evidence" items={evidenceState.data ? getArray(evidenceState.data) : getArray(valueAt(incident, "evidence", "relatedEvidence", "related_evidence"))} />
        <ResourceSubsection title="Indicators of compromise" items={indicatorState.data ? getArray(indicatorState.data) : getArray(valueAt(incident, "iocs", "indicators"))} />
      </aside></div>
    </>}
  </div>;
}

function IncidentEdit({ incident, onSaved }: { incident: JsonRecord; onSaved: () => void }) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const id = String(incident.id);
    const tags = String(form.get("tags") ?? "").split(",").map((tag) => tag.trim()).filter(Boolean);
    setSaving(true); setError("");
    try {
      await api.updateIncident(id, {
        severity: String(form.get("severity")),
        status: String(form.get("status")),
        assignee: String(form.get("assignee") ?? "") || null,
        root_cause: String(form.get("root_cause") ?? ""),
        business_impact: String(form.get("business_impact") ?? ""),
        containment_notes: String(form.get("containment_notes") ?? ""),
        remediation_notes: String(form.get("remediation_notes") ?? ""),
        resolution_notes: String(form.get("resolution_notes") ?? ""),
        tags,
      });
      onSaved();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Incident could not be updated."); }
    finally { setSaving(false); }
  };
  return <form className="panel form-card incident-edit" onSubmit={save}>
    <div className="settings-heading"><span className="form-icon"><Activity size={18} /></span><div><h2>Update investigation</h2><p>Status, ownership, and response notes</p></div></div>
    <div className="field-row"><label className="field"><span>Severity</span><select name="severity" defaultValue={String(incident.severity ?? "medium")}>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
      <label className="field"><span>Status</span><select name="status" defaultValue={String(incident.status ?? "new")}>{["new", "triaged", "investigating", "containment", "eradication", "recovery", "resolved", "closed"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label></div>
    <label className="field"><span>Assigned analyst</span><input name="assignee" defaultValue={String(incident.assignee ?? "")} maxLength={80} /></label>
    <label className="field"><span>Tags (comma-separated)</span><input name="tags" defaultValue={Array.isArray(incident.tags) ? incident.tags.join(", ") : ""} /></label>
    <label className="field"><span>Root cause</span><textarea name="root_cause" rows={2} defaultValue={String(incident.root_cause ?? "")} maxLength={10000} /></label>
    <label className="field"><span>Business impact</span><textarea name="business_impact" rows={2} defaultValue={String(incident.business_impact ?? "")} maxLength={10000} /></label>
    <label className="field"><span>Containment notes</span><textarea name="containment_notes" rows={2} defaultValue={String(incident.containment_notes ?? "")} maxLength={10000} /></label>
    <label className="field"><span>Remediation notes</span><textarea name="remediation_notes" rows={2} defaultValue={String(incident.remediation_notes ?? "")} maxLength={10000} /></label>
    <label className="field"><span>Resolution summary</span><textarea name="resolution_notes" rows={2} defaultValue={String(incident.resolution_notes ?? "")} maxLength={10000} /></label>
    {error && <div className="inline-error" role="alert"><AlertCircle size={16} />{error}</div>}
    <button className="button primary" disabled={saving}>{saving ? <LoaderCircle size={16} className="spin" /> : <Check size={16} />} Save investigation</button>
  </form>;
}

function ResourceSubsection({ title, items }: { title: string; items: unknown[] }) {
  return <section className="panel detail-panel"><div className="panel-header"><h2>{title}</h2><span className="tiny-count">{items.length}</span></div>{items.length ? <ul className="related-list">{items.map((item, index) => <li key={index}>{text(valueAt(asRecord(item), "name", "filename", "value", "id"))}</li>)}</ul> : <p className="muted-copy">No related records returned.</p>}</section>;
}

type ResourceType = "evidence" | "indicators" | "audit";
const resources: Record<ResourceType, { title: string; description: string; endpoint: () => Promise<unknown[]>; columns: [string, string][]; icon: typeof FolderSearch }> = {
  evidence: { title: "Evidence Vault", description: "Register evidence metadata and review recorded hashes. File uploads are intentionally disabled.", endpoint: api.evidence, icon: FolderSearch, columns: [["Evidence", "label"], ["Source", "source"], ["Incident", "incident_id"], ["Collected", "collected_at"], ["SHA-256", "sha256"], ["Reference", "reference"]] },
  indicators: { title: "Indicators of compromise", description: "Validate, search, and track IOC values linked to investigations.", endpoint: api.indicators, icon: Fingerprint, columns: [["Indicator", "value"], ["Type", "indicator_type"], ["Incident", "incident_id"], ["Confidence", "confidence"], ["Analyst notes", "notes"]] },
  audit: { title: "Audit log", description: "Read-only application history of security operations and account activity.", endpoint: api.audit, icon: FileClock, columns: [["Action", "action"], ["Actor ID", "actor_id"], ["Entity", "resource_type"], ["Entity ID", "resource_id"], ["Details", "details"], ["Timestamp", "occurred_at"]] },
};

function ResourcePage({ type }: { type: ResourceType }) {
  const config = resources[type];
  const state = useRemote(config.endpoint);
  const [query, setQuery] = useState("");
  const Icon = config.icon;
  const rows = getArray(state.data).filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase()));
  return <div className="page-content"><PageHeading eyebrow="INVESTIGATION DATA" title={config.title} description={config.description} action={type !== "audit" && rows.length ? <><button className="button secondary" onClick={() => exportRows(rows, "json", type)}><Download size={15} /> JSON</button><button className="button secondary" onClick={() => exportRows(rows, "csv", type)}><Download size={15} /> CSV</button></> : undefined} />
    {type === "evidence" && <EvidenceRegister onCreated={state.reload} />}
    {type === "indicators" && <IndicatorRegister onCreated={state.reload} />}
    <section className="panel table-panel"><div className="table-tools"><label className="search-box"><Search size={15} /><input aria-label={`Search ${config.title}`} placeholder={`Search ${config.title.toLowerCase()}…`} value={query} onChange={(e) => setQuery(e.target.value)} /></label><button className="button secondary compact" onClick={() => setQuery("")} disabled={!query}><Filter size={15} /> Clear search</button></div>
      {state.loading ? <LoadingState label={`Loading ${config.title.toLowerCase()}…`} /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : rows.length ? <div className="table-scroll"><table><thead><tr>{config.columns.map(([label]) => <th key={label}>{label}</th>)}{type === "evidence" && <th>Hash verification</th>}</tr></thead><tbody>{rows.map((raw, index) => { const row = asRecord(raw); const id = text(valueAt(row, "id"), String(index)); return <tr key={id}>{config.columns.map(([, key]) => { const value = readField(row, key); return <td key={key}>{key.toLowerCase().includes("sha256") ? <code className="hash-cell">{text(value)}</code> : /_at$|timestamp/i.test(key) ? formatDate(value) : text(value)}</td>; })}{type === "evidence" && <td><button className="text-button" disabled={!row.sha256} onClick={async () => { const candidate = window.prompt("Enter the SHA-256 of the analysis copy to compare with the recorded metadata hash."); if (!candidate) return; try { const result = await api.verifyEvidenceHash(id, candidate); window.alert(result.matches ? "Hash matches the recorded SHA-256. This does not prove evidence authenticity." : "Hash does not match the recorded SHA-256."); } catch (error) { window.alert(error instanceof Error ? error.message : "Hash verification failed."); } }}>Verify hash</button></td>}</tr>; })}</tbody></table></div> : <EmptyState title={`No ${config.title.toLowerCase()} found`} detail="Records will appear when created in the API." action={<span className="empty-icon"><Icon size={18} /></span>} />}
    </section></div>;
}

function EvidenceRegister({ onCreated }: { onCreated: () => void }) {
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const sha256 = String(form.get("sha256") ?? "").trim();
    if (sha256 && !/^[a-fA-F0-9]{64}$/.test(sha256)) { setError("SHA-256 must be exactly 64 hexadecimal characters."); return; }
    setSaving(true); setError("");
    try {
      await api.createEvidence({
        incident_id: Number(form.get("incident_id")),
        label: String(form.get("label")),
        source: String(form.get("source")),
        description: String(form.get("description") ?? ""),
        reference: String(form.get("reference") ?? "") || null,
        sha256: sha256 || null,
      });
      formElement.reset();
      onCreated();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Evidence metadata could not be registered."); }
    finally { setSaving(false); }
  };
  return <form className="panel form-card resource-form" onSubmit={submit}>
    <div className="settings-heading"><span className="form-icon"><FolderSearch size={18} /></span><div><h2>Register evidence metadata</h2><p>No files are uploaded or stored by this application.</p></div></div>
    <div className="field-row"><label className="field"><span>Incident ID</span><input name="incident_id" type="number" min="1" required /></label><label className="field"><span>Evidence name</span><input name="label" maxLength={200} required /></label><label className="field"><span>Collector / source</span><input name="source" maxLength={200} required /></label></div>
    <div className="field-row"><label className="field"><span>SHA-256 (optional)</span><input name="sha256" minLength={64} maxLength={64} pattern="[A-Fa-f0-9]{64}" /></label><label className="field"><span>Storage reference (optional)</span><input name="reference" maxLength={500} /></label><label className="field"><span>Description</span><input name="description" maxLength={5000} /></label></div>
    {error && <div className="inline-error" role="alert"><AlertCircle size={16} />{error}</div>}<button className="button primary" disabled={saving}>{saving ? <LoaderCircle size={16} className="spin" /> : <Plus size={16} />} Register metadata</button>
  </form>;
}

function IndicatorRegister({ onCreated }: { onCreated: () => void }) {
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    setSaving(true); setError("");
    try {
      await api.createIndicator({
        indicator_type: String(form.get("indicator_type")),
        value: String(form.get("value")).trim(),
        confidence: Number(form.get("confidence")),
        notes: String(form.get("notes") ?? ""),
        incident_id: form.get("incident_id") ? Number(form.get("incident_id")) : null,
      });
      formElement.reset();
      onCreated();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Indicator could not be registered."); }
    finally { setSaving(false); }
  };
  return <form className="panel form-card resource-form" onSubmit={submit}>
    <div className="settings-heading"><span className="form-icon"><Fingerprint size={18} /></span><div><h2>Add indicator</h2><p>Indicators are stored as untrusted text and are never visited automatically.</p></div></div>
    <div className="field-row"><label className="field"><span>Type</span><select name="indicator_type" required>{["ip", "domain", "url", "email", "hash"].map((kind) => <option key={kind} value={kind}>{kind}</option>)}</select></label><label className="field"><span>Indicator value</span><input name="value" maxLength={253} required /></label><label className="field"><span>Confidence (0–100)</span><input name="confidence" type="number" min="0" max="100" defaultValue="50" required /></label></div>
    <div className="field-row"><label className="field"><span>Related incident ID (optional)</span><input name="incident_id" type="number" min="1" /></label><label className="field"><span>Analyst notes</span><input name="notes" maxLength={5000} /></label></div>
    {error && <div className="inline-error" role="alert"><AlertCircle size={16} />{error}</div>}<button className="button primary" disabled={saving}>{saving ? <LoaderCircle size={16} className="spin" /> : <Plus size={16} />} Add indicator</button>
  </form>;
}

function exportRows(rows: unknown[], format: "csv" | "json", type: ResourceType) {
  const content = format === "json"
    ? JSON.stringify(rows, null, 2)
    : [Object.keys(asRecord(rows[0])).join(","), ...rows.map((raw) => Object.values(asRecord(raw)).map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(","))].join("\r\n");
  const blob = new Blob([content], { type: format === "json" ? "application/json" : "text/csv" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `cybershield-${type}.${format}`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function Analytics() {
  const state = useRemote(api.analytics);
  const data = unwrapRecord(state.data);
  const trends = getArray(data.trend);
  const severities = Object.entries(asRecord(data.severity)).map(([severity, count]) => ({ severity, count }));
  const categories = Object.entries(asRecord(data.category)).map(([category, count]) => ({ category, count }));
  const statuses = asRecord(data.status);
  const openCount = Object.entries(statuses).reduce((sum, [status, count]) => sum + (["resolved", "closed"].includes(status) ? 0 : Number(count)), 0);
  const resolvedCount = Number(statuses.resolved ?? 0) + Number(statuses.closed ?? 0);
  const workload = getArray(data.analyst_workload);
  const metricCards: { label: string; value: string | number; icon: typeof ShieldAlert; tone: string; note: string }[] = [
    { label: "Open incidents", value: openCount, icon: ShieldAlert, tone: "red", note: "Database-derived" },
    { label: "Resolved / closed", value: resolvedCount, icon: ShieldCheck, tone: "green", note: "Database-derived" },
    { label: "Analyst workload", value: workload.length, icon: UserRound, tone: "blue", note: "Assigned analyst count" },
    { label: "Mean time to resolve", value: text(data.resolution_time, "Insufficient data"), icon: Clock3, tone: "amber", note: text(data.resolution_time_note) },
  ];
  return <div className="page-content"><PageHeading eyebrow="SECURITY INTELLIGENCE" title="Analytics" description="Operational trends and response performance from your security data." action={<button className="button secondary" onClick={() => window.print()}><Download size={16} /> Export view</button>} />
    {state.loading ? <LoadingState label="Loading analytics…" /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : <div className="analytics-content">
      <div className="metric-grid">{metricCards.map(({ label, value, icon: Icon, tone, note }) => <article className="metric-card" key={label}><div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon size={17} /></span></div><div className="metric-value">{text(value)}</div><div className="metric-foot"><span>{note}</span></div></article>)}</div>
      <div className="dashboard-grid"><section className="panel chart-panel"><div className="panel-header"><div><h2>Incident trend</h2><p>Cases grouped by creation date</p></div></div>{trends.length ? <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={trends}><CartesianGrid strokeDasharray="4 5" stroke="var(--border)" vertical={false} /><XAxis dataKey="date" tick={{ fill: "var(--muted)", fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: "var(--panel)", border: "1px solid var(--border)", borderRadius: 9, color: "var(--text)" }} /><Area type="monotone" dataKey="count" stroke="#36d6a5" fill="#36d6a522" /></AreaChart></ResponsiveContainer></div> : <EmptyState title="No trend data" detail="The API has not returned trend series." />}</section><section className="panel chart-panel"><div className="panel-header"><div><h2>Severity distribution</h2><p>Breakdown from your incident data</p></div></div><SeverityBreakdown data={severities} /></section></div>
      <div className="dashboard-grid"><section className="panel chart-panel"><div className="panel-header"><div><h2>Incidents by category</h2><p>Counts calculated from stored incident records</p></div></div>{categories.length ? <div className="category-count-list">{categories.map((row) => <div key={row.category}><span>{row.category}</span><b>{text(row.count)}</b></div>)}</div> : <EmptyState title="No category data" detail="Category counts will appear as incidents are recorded." />}</section><section className="panel chart-panel"><div className="panel-header"><div><h2>Analyst workload</h2><p>Records assigned per analyst</p></div></div>{workload.length ? <div className="category-count-list">{workload.map((raw, index) => { const row = asRecord(raw); return <div key={`${text(row.analyst)}-${index}`}><span>{text(row.analyst)}</span><b>{text(row.count)}</b></div>; })}</div> : <EmptyState title="No analyst assignments" detail="Assign an analyst to incidents to see workload counts." />}</section></div>
    </div>}</div>;
}

function Reports() {
  const [reportId, setReportId] = useState("");
  const [html, setHtml] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const openReport = async (event: FormEvent) => {
    event.preventDefault();
    if (!reportId.trim()) return;
    setBusy(true); setError(""); setHtml(null);
    try { setHtml(await api.report(reportId.trim())); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Could not load the report."); }
    finally { setBusy(false); }
  };
  const downloadReport = () => {
    if (!html) return;
    const url = URL.createObjectURL(new Blob([html], { type: "text/html;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `cybershield-incident-${reportId}.html`;
    anchor.click();
    URL.revokeObjectURL(url);
  };
  return <div className="page-content"><PageHeading eyebrow="DOCUMENTATION" title="Reports" description="Retrieve and download printable reports generated from recorded incident facts." action={html ? <><button className="button secondary" onClick={downloadReport}><Download size={15} /> Download HTML</button><button className="button secondary" onClick={() => window.print()}><FileText size={15} /> Print view</button></> : undefined} />
    <section className="panel report-panel"><form className="report-lookup" onSubmit={openReport}><label className="field"><span>Report ID</span><input value={reportId} onChange={(event) => setReportId(event.target.value)} placeholder="Enter report ID" required /></label><button className="button primary" disabled={busy || !reportId.trim()}>{busy ? <LoaderCircle className="spin" size={16} /> : <FileText size={16} />} Open report</button></form>
      {busy && <LoadingState label="Loading report…" />}
      {error && <div className="inline-error" role="alert"><AlertCircle size={16} />{error}</div>}
      {html !== null && <iframe className="report-preview" title={`Report ${reportId}`} sandbox="" srcDoc={html} />}
      {html === null && !busy && !error && <EmptyState title="No report selected" detail="Enter an existing report ID to retrieve its HTML from the API." />}
    </section>
  </div>;
}

function Settings({ onSaved }: { onSaved: (message: string) => void }) {
  const [emailAlerts, setEmailAlerts] = useState(() => localStorage.getItem("cybershield.preference.email") === "true");
  const [slackAlerts, setSlackAlerts] = useState(() => localStorage.getItem("cybershield.preference.slack") === "true");
  const save = () => {
    localStorage.setItem("cybershield.preference.email", String(emailAlerts));
    localStorage.setItem("cybershield.preference.slack", String(slackAlerts));
    onSaved("Local browser preferences saved");
  };
  return <div className="page-content"><PageHeading eyebrow="PREFERENCES" title="Settings" description="Browser-level preferences and configuration guidance." action={<button className="button primary" onClick={save}><Check size={16} /> Save preferences</button>} />
    <section className="panel settings-panel"><div className="settings-heading"><span className="form-icon"><Bell size={18} /></span><div><h2>Notification preferences</h2><p>These are local display preferences only; delivery integrations are not configured.</p></div></div>
      <ToggleRow title="Email alert preference" detail="Remember that email notifications are desired. No email is sent." checked={emailAlerts} onChange={setEmailAlerts} />
      <ToggleRow title="Chat alert preference" detail="Remember that chat notifications are desired. No chat integration is configured." checked={slackAlerts} onChange={setSlackAlerts} />
    </section>
    <section className="panel settings-panel"><div className="settings-heading"><span className="form-icon"><LockKeyhole size={18} /></span><div><h2>Service configuration</h2><p>Environment-managed values are intentionally not exposed by the API.</p></div></div><dl className="metadata-list">
      <div><dt>API endpoint</dt><dd>{import.meta.env.VITE_API_BASE_URL || "/api/v1"}</dd></div>
      <div><dt>Evidence handling</dt><dd>Metadata-only; no file upload is enabled</dd></div>
      <div><dt>Database</dt><dd>Configured on the backend; private connection details are not exposed</dd></div>
      <div><dt>Authentication</dt><dd>Bearer token with server-side role checks</dd></div>
    </dl></section>
  </div>;
}

function ToggleRow({ title, detail, checked, onChange }: { title: string; detail: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <div className="toggle-row"><span><b>{title}</b><small>{detail}</small></span><button type="button" role="switch" aria-checked={checked} aria-label={title} className={`switch ${checked ? "checked" : ""}`} onClick={() => onChange(!checked)}><i /></button></div>;
}

const loginSchema = z.object({ username: z.string().trim().min(1, "Username is required."), password: z.string().min(1, "Password is required.") });
type LoginInput = z.infer<typeof loginSchema>;
function Login({ onLogin }: { onLogin: (user: LoginResponse["user"]) => void }) {
  const [apiError, setApiError] = useState("");
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<LoginInput>({ resolver: zodResolver(loginSchema) });
  const submit = async (values: LoginInput) => {
    setApiError("");
    try {
      const result = await api.login(values.username, values.password);
      if (!result?.access_token || !result.user) throw new ApiError("The authentication response was incomplete.", 502);
      setToken(result.access_token, result.token_type || "Bearer");
      onLogin(result.user);
    } catch (reason) { setApiError(reason instanceof Error ? reason.message : "Unable to sign in."); }
  };
  return <main className="login-layout"><section className="login-aside"><div className="brand login-brand"><span className="brand-mark"><Shield size={20} /></span><span>CYBER<span className="brand-accent">SHIELD</span><small>SECURITY OPERATIONS</small></span></div><div className="login-aside-copy"><div className="login-orbit"><span><ShieldCheck size={38} /></span><i /><i /><i /></div><p className="eyebrow">ONE PLATFORM. FULL VISIBILITY.</p><h1>Stay ahead of<br /><span>every threat.</span></h1><p>Investigate incidents, correlate evidence, and coordinate your response from a unified security workspace.</p></div>  <div className="login-footer"><span><LockKeyhole size={13} /> Secure workspace access</span><span>CyberShield</span></div></section>
    <section className="login-main"><form className="login-form" onSubmit={handleSubmit(submit)}><div className="mobile-login-brand brand"><span className="brand-mark"><Shield size={19} /></span><span>CYBER<span className="brand-accent">SHIELD</span><small>SECURITY OPERATIONS</small></span></div><div className="login-title"><div className="login-lock"><LockKeyhole size={20} /></div><p className="eyebrow">SECURE ACCESS</p><h2>Welcome back</h2><p>Sign in to your security operations workspace.</p></div>
      <label className="field"><span>Username</span><input type="text" autoComplete="username" placeholder="Enter your username" {...register("username")} aria-invalid={Boolean(errors.username)} />{errors.username && <small className="field-error">{errors.username.message}</small>}</label>
      <label className="field"><span>Password</span><input type="password" autoComplete="current-password" placeholder="Enter your password" {...register("password")} aria-invalid={Boolean(errors.password)} />{errors.password && <small className="field-error">{errors.password.message}</small>}</label>
      {apiError && <div className="inline-error" role="alert"><AlertCircle size={16} />{apiError}</div>}
      <button className="button primary login-submit" disabled={isSubmitting}>{isSubmitting ? <LoaderCircle size={17} className="spin" /> : <LockKeyhole size={16} />} Sign in securely <ArrowRight size={16} /></button>
      <div className="login-footnote"><LockKeyhole size={13} /> Protected by server-side authentication</div>
        <p className="login-help">Need access? Contact your workspace administrator.</p>
    </form></section></main>;
}

export default App;
