import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserRouter } from "react-router-dom";
import App from "./App";

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
});

function renderApp() {
  return render(<BrowserRouter><App /></BrowserRouter>);
}

describe("CyberShield application", () => {
  it("renders a login form when no bearer token is present", () => {
    renderApp();
    expect(screen.getByRole("heading", { name: "Welcome back" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in securely/i })).toBeInTheDocument();
  });

  it("shows API authentication errors without entering the dashboard", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ message: "Invalid credentials" }), {
      status: 401, headers: { "content-type": "application/json" },
    }));
    renderApp();
    await userEvent.type(screen.getByLabelText("Username"), "analyst");
    await userEvent.type(screen.getByLabelText("Password"), "bad-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in securely/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid credentials");
    expect(screen.queryByText("Overview")).not.toBeInTheDocument();
  });

  it("loads the responsive dashboard after successful authentication", async () => {
    localStorage.setItem("cybershield.token", "valid-token");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", {
      status: 200, headers: { "content-type": "application/json" },
    }));
    renderApp();
    expect(await screen.findByRole("heading", { name: "Security operations overview" })).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/dashboard", expect.anything()));
    expect(screen.getByRole("button", { name: "Open navigation" })).toBeInTheDocument();
    expect(screen.getByText("No recent incidents")).toBeInTheDocument();
    expect(screen.queryByText("8")).not.toBeInTheDocument();
  });

  it("posts backend login fields and stores the returned access token type", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      if (String(input) === "/api/v1/auth/login") {
        return new Response(JSON.stringify({ access_token: "signed-in-token", token_type: "Token", user: { username: "analyst" } }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    });
    renderApp();
    await userEvent.type(screen.getByLabelText("Username"), "analyst");
    await userEvent.type(screen.getByLabelText("Password"), "passphrase");
    await userEvent.click(screen.getByRole("button", { name: /sign in securely/i }));
    expect(await screen.findByRole("heading", { name: "Security operations overview" })).toBeInTheDocument();
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ username: "analyst", password: "passphrase" });
    expect(localStorage.getItem("cybershield.token")).toBe("signed-in-token");
    expect(localStorage.getItem("cybershield.token-type")).toBe("Token");
    await waitFor(() => expect(fetchMock.mock.calls[1][1]?.headers).toBeDefined());
    expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get("Authorization")).toBe("Token signed-in-token");
  });

  it("renders the paginated incidents response and requests the next page", async () => {
    localStorage.setItem("cybershield.token", "valid-token");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url === "/api/v1/dashboard") {
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      }
      if (url.includes("page=2&page_size=25")) {
        return new Response(JSON.stringify({ items: [{ id: "inc-26", title: "Second page incident" }], total: 26, page: 2, page_size: 25 }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      const items = Array.from({ length: 25 }, (_, index) => ({ id: `inc-${index + 1}`, title: `Incident ${index + 1}`, status: "Open", severity: "Medium" }));
      return new Response(JSON.stringify({ items, total: 26, page: 1, page_size: 25 }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    });
    renderApp();
    await userEvent.click(await screen.findByRole("link", { name: "Incidents" }));
    expect(await screen.findByText("Incident 1")).toBeInTheDocument();
    expect(screen.getByText("Page 1 of 2")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(await screen.findByText("Second page incident")).toBeInTheDocument();
    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).includes("/api/v1/incidents?page=2&page_size=25"))).toBe(true));
  });

  it("reviews imported alerts and promotes them without mixing them into the incident queue", async () => {
    localStorage.setItem("cybershield.token", "valid-token");
    let promoted = false;
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url === "/api/v1/dashboard") {
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      }
      if (url === "/api/v1/import/alerts/9/promote") {
        promoted = true;
        return new Response(JSON.stringify({ incident_id: "incident-55" }), {
          status: 201, headers: { "content-type": "application/json" },
        });
      }
      if (url === "/api/v1/import/alerts?review_status=pending") {
        const alerts = promoted ? [] : [{ id: 9, source_id: "source-alert-9", title: "Suspicious source alert", source_system: "EDR sensor", source_timestamp: "2026-10-26T10:00:00Z", review_status: "pending" }];
        return new Response(JSON.stringify(alerts), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (url === "/api/v1/import/alerts?review_status=promoted") {
        const alerts = promoted ? [{ id: 9, source_id: "source-alert-9", title: "Suspicious source alert", source_system: "EDR sensor", source_timestamp: "2026-10-26T10:00:00Z", review_status: "promoted" }] : [];
        return new Response(JSON.stringify(alerts), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (url.startsWith("/api/v1/incidents?")) {
        return new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 25 }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 25 }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    });
    renderApp();
    await userEvent.click(await screen.findByRole("link", { name: "Imported alerts" }));
    expect(await screen.findByText("Suspicious source alert")).toBeInTheDocument();
    expect(screen.getByText("source-alert-9")).toBeInTheDocument();
    expect(screen.getByText("EDR sensor")).toBeInTheDocument();
    expect(screen.getByText("Pending")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Promote to incident" }));
    expect(await screen.findByText("No imported alerts")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Promote to incident" })).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/import/alerts/9/promote", expect.objectContaining({ method: "POST" }));
    expect(fetchMock.mock.calls.filter(([url]) => url === "/api/v1/import/alerts?review_status=pending").length).toBeGreaterThanOrEqual(2);
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Alert review status" }), "promoted");
    expect((await screen.findAllByText("Promoted")).length).toBeGreaterThanOrEqual(1);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/import/alerts?review_status=promoted", expect.any(Object));
    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith("/api/v1/incidents?"))).toBe(true));
  });

  it("sends creation-date and sorting controls to the server-side incident filters", async () => {
    localStorage.setItem("cybershield.token", "valid-token");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      items: [], total: 0, page: 1, page_size: 25,
    }), { status: 200, headers: { "content-type": "application/json" } }));
    renderApp();
    await userEvent.click(await screen.findByRole("link", { name: "Incidents" }));
    fireEvent.change(screen.getByLabelText("Created from"), { target: { value: "2026-10-01" } });
    fireEvent.change(screen.getByLabelText("Created to"), { target: { value: "2026-10-26" } });
    await userEvent.selectOptions(screen.getByLabelText("Sort by"), "severity");
    await userEvent.selectOptions(screen.getByLabelText("Sort order"), "asc");
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map(([url]) => String(url));
      expect(urls).toContain("/api/v1/incidents?page=1&page_size=25&date_from=2026-10-01&date_to=2026-10-26&sort_by=severity&sort_order=asc");
    });
  });
});
