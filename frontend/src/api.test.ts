import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, getToken, request, setToken } from "./api";

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe("API client", () => {
  it("sends bearer auth and JSON headers for authenticated requests", async () => {
    setToken("session-token", "Token");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: true }), {
      status: 200, headers: { "content-type": "application/json" },
    }));
    await expect(request<{ ok: boolean }>("/incidents", { method: "POST", body: JSON.stringify({ title: "Alert" }) })).resolves.toEqual({ ok: true });
    const headers = new Headers(fetchMock.mock.calls[0][1]?.headers);
    expect(headers.get("Authorization")).toBe("Token session-token");
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("does not invent successful results for API errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ message: "Not authorized" }), {
      status: 401, headers: { "content-type": "application/json" },
    }));
    await expect(request("/incidents")).rejects.toMatchObject({ name: "ApiError", status: 401, message: "Not authorized" });
  });

  it("removes tokens on sign out", () => {
    setToken("session-token");
    expect(getToken()).toBe("session-token");
    setToken(null);
    expect(getToken()).toBeNull();
  });

  it("reports unavailable API connections as errors", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("offline"));
    await expect(request("/dashboard")).rejects.toBeInstanceOf(ApiError);
  });

  it("uses the backend paths, payloads, and pagination contract", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/reports/report-7")) {
        return new Response("<html><body>Report</body></html>", { status: 200, headers: { "content-type": "text/html" } });
      }
      if (url.endsWith("/incidents?page=3&page_size=40")) {
        return new Response(JSON.stringify({ items: [], total: 81, page: 3, page_size: 40 }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/dashboard")) {
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response(JSON.stringify({ access_token: "access", token_type: "Bearer", user: { username: "analyst" } }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    });

    const login = await api.login("analyst", "password");
    expect(login).toEqual({ access_token: "access", token_type: "Bearer", user: { username: "analyst" } });
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ username: "analyst", password: "password" });
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/v1/auth/login");
    await api.dashboard();
    expect(String(fetchMock.mock.calls[1][0])).toBe("/api/v1/dashboard");
    expect(await api.incidents(3, 40)).toEqual({ items: [], total: 81, page: 3, page_size: 40 });
    expect(String(fetchMock.mock.calls[2][0])).toBe("/api/v1/incidents?page=3&page_size=40");
    await api.indicators();
    expect(String(fetchMock.mock.calls[3][0])).toBe("/api/v1/indicators");
    await api.audit();
    expect(String(fetchMock.mock.calls[4][0])).toBe("/api/v1/audit");
    await expect(api.report("report-7")).resolves.toContain("<html>");
    expect(String(fetchMock.mock.calls[5][0])).toBe("/api/v1/reports/report-7");

    const form = new FormData();
    form.append("file", "alert-feed");
    await api.importAlerts(form);
    const [url, init] = fetchMock.mock.calls[6];
    expect(String(url)).toBe("/api/v1/import/alerts");
    expect(init?.body).toBe(form);
    expect(new Headers(init?.headers).has("Content-Type")).toBe(false);
  });

  it("lists imported alerts and promotes a selected alert through the API", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/import/alerts/source%2Falert-7/promote")) {
        return new Response(JSON.stringify({ id: "incident-12" }), {
          status: 201, headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/import/alerts?review_status=pending")) {
        return new Response(JSON.stringify([{ id: "source/alert-7", status: "pending" }]), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      return new Response("Not found", { status: 404 });
    });

    await expect(api.importedAlerts()).resolves.toEqual([{ id: "source/alert-7", status: "pending" }]);
    await expect(api.promoteImportedAlert("source/alert-7")).resolves.toEqual({ id: "incident-12" });
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/v1/import/alerts?review_status=pending");
    expect(String(fetchMock.mock.calls[0][1]?.method ?? "GET")).toBe("GET");
    expect(String(fetchMock.mock.calls[1][0])).toBe("/api/v1/import/alerts/source%2Falert-7/promote");
    expect(fetchMock.mock.calls[1][1]?.method).toBe("POST");
  });

  it("requests the selected imported-alert review status", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("[]", {
      status: 200, headers: { "content-type": "application/json" },
    }));
    await api.importedAlerts("promoted");
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/v1/import/alerts?review_status=promoted");
  });

  it("serializes incident date range and sort filters using backend query names", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      items: [], total: 0, page: 2, page_size: 25,
    }), { status: 200, headers: { "content-type": "application/json" } }));

    await api.incidents({
      page: 2,
      pageSize: 25,
      severity: "high",
      status: "investigating",
      category: "phishing",
      assignee: "analyst",
      search: "mail alert",
      createdFrom: "2026-10-01",
      createdTo: "2026-10-26",
      sortBy: "created_at",
      sortOrder: "desc",
    });

    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "/api/v1/incidents?page=2&page_size=25&severity=high&status=investigating&category=phishing&assignee=analyst&search=mail+alert&date_from=2026-10-01&date_to=2026-10-26&sort_by=created_at&sort_order=desc",
    );
  });
});
