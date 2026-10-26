export const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api/v1";
export const DEFAULT_PAGE_SIZE = 25;

export interface IncidentPage {
  items: unknown[];
  total: number;
  page: number;
  page_size: number;
}

export interface IncidentFilters {
  page?: number;
  pageSize?: number;
  severity?: string;
  status?: string;
  category?: string;
  assignee?: string;
  search?: string;
  createdFrom?: string;
  createdTo?: string;
  sortBy?: "created_at" | "severity" | "updated_at";
  sortOrder?: "asc" | "desc";
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: {
    id: number;
    username: string;
    email: string;
    role: "admin" | "analyst" | "viewer";
    is_active: boolean;
  };
}

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function getToken(): string | null {
  return localStorage.getItem("cybershield.token");
}

export function getTokenType(): string {
  return localStorage.getItem("cybershield.token-type") ?? "Bearer";
}

export function setToken(token: string | null, tokenType = "Bearer"): void {
  if (token) {
    localStorage.setItem("cybershield.token", token);
    localStorage.setItem("cybershield.token-type", tokenType);
  } else {
    localStorage.removeItem("cybershield.token");
    localStorage.removeItem("cybershield.token-type");
  }
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `${getTokenType()} ${token}`);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError("Unable to reach the CyberShield API. Check your connection and try again.", 0);
  }

  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("application/json")
    ? await response.json().catch(() => null)
    : await response.text().catch(() => "");

  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "message" in payload
        ? String(payload.message)
        : payload && typeof payload === "object" && ("error" in payload || "detail" in payload)
          ? String("error" in payload ? payload.error : payload.detail)
          : typeof payload === "string" && payload
            ? payload
            : `Request failed (${response.status})`;
    throw new ApiError(detail, response.status);
  }
  return payload as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<LoginResponse["user"]>("/auth/me"),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  dashboard: () => request<Record<string, unknown>>("/dashboard"),
  incidents: (filters: IncidentFilters | number = {}, requestedPageSize = DEFAULT_PAGE_SIZE) => {
    const options: IncidentFilters = typeof filters === "number"
      ? { page: filters, pageSize: requestedPageSize }
      : filters;
    const params = new URLSearchParams();
    params.set("page", String(options.page ?? 1));
    params.set("page_size", String(options.pageSize ?? DEFAULT_PAGE_SIZE));
    const queryFilters = [
      ["severity", options.severity],
      ["status", options.status],
      ["category", options.category],
      ["assignee", options.assignee],
      ["search", options.search],
      ["date_from", options.createdFrom],
      ["date_to", options.createdTo],
      ["sort_by", options.sortBy],
      ["sort_order", options.sortOrder],
    ] as const;
    for (const [key, value] of queryFilters) {
      if (value) params.set(key, value);
    }
    return request<IncidentPage>(`/incidents?${params.toString()}`);
  },
  incident: (id: string) => request<Record<string, unknown>>(`/incidents/${encodeURIComponent(id)}`),
  createIncident: (body: unknown) =>
    request<Record<string, unknown>>("/incidents", { method: "POST", body: JSON.stringify(body) }),
  evidence: (incidentId?: string) =>
    request<unknown[]>(`/evidence${incidentId ? `?incident_id=${encodeURIComponent(incidentId)}` : ""}`),
  createEvidence: (body: unknown) =>
    request<Record<string, unknown>>("/evidence", { method: "POST", body: JSON.stringify(body) }),
  verifyEvidenceHash: (id: number | string, sha256: string) =>
    request<{ evidence_id: number; has_recorded_hash: boolean; matches: boolean }>(`/evidence/${id}/verify-hash`, {
      method: "POST",
      body: JSON.stringify({ sha256 }),
    }),
  indicators: (incidentId?: string) =>
    request<unknown[]>(`/indicators${incidentId ? `?incident_id=${encodeURIComponent(incidentId)}` : ""}`),
  createIndicator: (body: unknown) =>
    request<Record<string, unknown>>("/indicators", { method: "POST", body: JSON.stringify(body) }),
  timeline: (incidentId: string) =>
    request<unknown[]>(`/incidents/${encodeURIComponent(incidentId)}/timeline`),
  analytics: () => request<Record<string, unknown>>("/analytics"),
  report: (id: string) => request<string>(`/reports/${encodeURIComponent(id)}`),
  audit: () => request<unknown[]>("/audit"),
  importAlerts: (form: FormData) =>
    request<Record<string, unknown>>("/import/alerts", { method: "POST", body: form }),
  importedAlerts: (reviewStatus: "pending" | "promoted" = "pending") =>
    request<unknown[]>(`/import/alerts?review_status=${reviewStatus}`),
  promoteImportedAlert: (id: string) =>
    request<Record<string, unknown>>(`/import/alerts/${encodeURIComponent(id)}/promote`, { method: "POST" }),
  updateIncident: (id: string, body: unknown) =>
    request<Record<string, unknown>>(`/incidents/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  addTimelineEvent: (id: string, body: unknown) =>
    request<Record<string, unknown>>(`/incidents/${encodeURIComponent(id)}/timeline`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
};
