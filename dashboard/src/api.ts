import type {
  CouncilDetail,
  EventDetailOut,
  EventOut,
  RegulationExposure,
  Summary,
  Timeseries,
} from "./types";

const BASE = "/v1/dashboard";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  summary: (hours: number) => get<Summary>(`/summary?hours=${hours}`),
  timeseries: (hours: number, buckets = 36) =>
    get<Timeseries>(`/timeseries?hours=${hours}&buckets=${buckets}`),
  regulations: (hours: number) => get<RegulationExposure>(`/regulations?hours=${hours}`),
  events: (params: Record<string, string | number | boolean | undefined>) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") qs.set(k, String(v));
    }
    return get<EventOut[]>(`/events?${qs.toString()}`);
  },
  event: (id: string) => get<EventDetailOut>(`/events/${id}`),
  council: (id: string) => get<CouncilDetail>(`/council/${id}`),
  acknowledge: async (id: string, acknowledged_by: string, note?: string) => {
    const res = await fetch(`${BASE}/events/${id}/acknowledge`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ acknowledged_by, note }),
    });
    if (!res.ok) throw new Error(`acknowledge -> ${res.status}`);
    return res.json() as Promise<EventOut>;
  },
  reportUrl: (hours: number, fmt: "json" | "markdown") =>
    `${BASE}/report?hours=${hours}&fmt=${fmt}`,
};

export function liveSocketUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/v1/live`;
}
