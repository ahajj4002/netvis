import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";

import App from "../App";

function jsonResponse(data, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
  });
}

function createFetchMock() {
  return vi.fn(async (input) => {
    const url = typeof input === "string" ? input : input?.url || "";

    if (url.includes("/api/status")) {
      return jsonResponse({
        local_ip: "10.0.0.2",
        gateway_ip: "10.0.0.1",
        network: "10.0.0.0/24",
        capturing: false,
        mitm_active: false,
        interfaces: [],
        scan_profiles: ["quick", "standard", "deep"],
        scapy_available: false,
        nmap_available: false,
        db_path: "test.db",
        api_key_enabled: false,
      });
    }
    if (url.includes("/api/devices")) return jsonResponse({ devices: [], count: 0 });
    if (url.includes("/api/connections")) return jsonResponse({ connections: [] });
    if (url.includes("/api/stats")) {
      return jsonResponse({
        total_bytes: 0,
        total_packets: 0,
        internal_traffic: 0,
        external_traffic: 0,
        top_talkers: [],
        protocol_breakdown: {},
        app_breakdown: {},
      });
    }
    if (url.includes("/api/dns")) {
      return jsonResponse({
        total_queries: 0,
        top_domains: [],
        queries_by_ip: {},
      });
    }
    if (url.includes("/api/alerts")) return jsonResponse({ alerts: [] });
    if (url.includes("/api/intel/story")) {
      return jsonResponse({
        summary: "No telemetry yet.",
        insights: [],
        top_domains: [],
        exposed_services: [],
      });
    }
    if (url.includes("/api/nip/daemon/status")) {
      return jsonResponse({ daemon: { running: false, baseline_hosts: 0, last_tick_at: "" } });
    }
    if (url.includes("/api/nip/techniques")) return jsonResponse({ techniques: [] });
    if (url.includes("/api/nip/events")) return jsonResponse({ events: [] });
    if (url.includes("/api/nip/metrics")) return jsonResponse({ metrics: [] });
    if (url.includes("/api/nip/baselines")) return jsonResponse({ baseline: null });
    if (url.includes("/api/coursework/status")) return jsonResponse({});
    if (url.includes("/api/coursework/jobs")) return jsonResponse({ jobs: [] });

    return jsonResponse({});
  });
}

describe("App smoke tests", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", createFetchMock());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders top-level navigation and controls", async () => {
    render(<App />);

    expect(await screen.findByRole("button", { name: /Graph/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Dashboard/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Workbench/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Scan Network/i })).toBeInTheDocument();
  });

  it("loads dashboard core panels", async () => {
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: /Dashboard/i }));

    expect(await screen.findByText(/^TIMELINE \(/i)).toBeInTheDocument();
    expect(screen.getByText(/SECURITY ALERTS/i)).toBeInTheDocument();
  });

  it("loads NIP console view", async () => {
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: /NIP/i }));

    expect(await screen.findByText(/NIP Console/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Metrics$/i })).toBeInTheDocument();
  });
});
