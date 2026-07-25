import { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { ActivityChart } from "./components/ActivityChart";
import { CategoryBar } from "./components/CategoryBar";
import { EventDrawer } from "./components/EventDrawer";
import { EventsTable } from "./components/EventsTable";
import { RegulationList } from "./components/RegulationList";
import { StatTile } from "./components/StatTile";
import { TopActors, TopDetectors } from "./components/TopLists";
import type { RegulationExposure, Severity, Summary, Timeseries } from "./types";
import { useLiveFeed } from "./useLiveFeed";
import "./App.css";

const WINDOWS = [
  { label: "1h", hours: 1 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 24 * 7 },
  { label: "30d", hours: 24 * 30 },
];

type Theme = "system" | "light" | "dark";

export default function App() {
  const [hours, setHours] = useState(24);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [series, setSeries] = useState<Timeseries | null>(null);
  const [regulations, setRegulations] = useState<RegulationExposure | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | "">("");
  const [theme, setTheme] = useState<Theme>("system");
  const [error, setError] = useState<string | null>(null);

  const { events, connected, flash } = useLiveFeed();

  useEffect(() => {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [s, t, r] = await Promise.all([
          api.summary(hours),
          api.timeseries(hours),
          api.regulations(hours),
        ]);
        if (cancelled) return;
        setSummary(s);
        setSeries(t);
        setRegulations(r);
        setError(null);
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
    }
    load();
    const interval = setInterval(load, 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [hours]);

  const visibleEvents = useMemo(
    () => (severityFilter ? events.filter((e) => e.severity === severityFilter) : events),
    [events, severityFilter],
  );

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <div>
            <div className="brand-title">Prompt Gateway</div>
            <div className="brand-subtitle">Outbound LLM prompt security</div>
          </div>
        </div>

        <div className="header-controls">
          <span className={`live-dot ${connected ? "live-on" : "live-off"}`} />
          <span className="live-label">{connected ? "Live" : "Reconnecting…"}</span>

          <div className="window-tabs">
            {WINDOWS.map((w) => (
              <button
                key={w.hours}
                className={hours === w.hours ? "tab active" : "tab"}
                onClick={() => setHours(w.hours)}
              >
                {w.label}
              </button>
            ))}
          </div>

          <select
            className="theme-select"
            value={theme}
            onChange={(e) => setTheme(e.target.value as Theme)}
            aria-label="Theme"
          >
            <option value="system">System</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>

          <a
            className="report-link"
            href={api.reportUrl(hours, "markdown")}
            target="_blank"
            rel="noreferrer"
          >
            Digest ↗
          </a>
        </div>
      </header>

      {error && <div className="app-banner">Could not reach the gateway: {error}</div>}

      <main className="app-main">
        <section className="stat-grid">
          <StatTile
            label="Prompts scanned"
            value={summary?.totals.events ?? "—"}
            delta={summary?.totals.change_pct ?? null}
            sublabel={`last ${hours}h`}
          />
          <StatTile
            label="Blocked"
            value={summary?.totals.blocked ?? "—"}
            tone="critical"
            sublabel="never transmitted"
          />
          <StatTile
            label="Redacted"
            value={summary?.totals.redacted ?? "—"}
            tone="serious"
            sublabel="masked, then sent"
          />
          <StatTile
            label="Open criticals"
            value={summary?.totals.open_criticals ?? "—"}
            tone={summary && summary.totals.open_criticals > 0 ? "critical" : "good"}
            sublabel="unacknowledged"
          />
          <StatTile
            label="Retro escalations"
            value={summary?.totals.retro_escalations ?? "—"}
            tone={summary && summary.totals.retro_escalations > 0 ? "warning" : "good"}
            sublabel="council caught it late"
          />
          <StatTile
            label="Council spend"
            value={summary ? `$${summary.performance.council_cost_usd.toFixed(2)}` : "—"}
            sublabel={summary ? `avg ${summary.performance.council_avg_ms.toFixed(0)} ms` : ""}
          />
        </section>

        <section className="grid-2">
          <div className="panel">
            <div className="panel-title">Activity by outcome</div>
            <ActivityChart data={series} />
          </div>
          <div className="panel">
            <div className="panel-title">Findings by category</div>
            <CategoryBar data={summary?.by_category ?? null} />
          </div>
        </section>

        <section className="grid-3">
          <div className="panel">
            <div className="panel-title">Regulatory exposure</div>
            <RegulationList data={regulations} />
          </div>
          <div className="panel">
            <div className="panel-title">Top detectors</div>
            <TopDetectors data={summary?.top_detectors ?? []} />
          </div>
          <div className="panel">
            <div className="panel-title">Highest-risk actors</div>
            <TopActors data={summary?.top_actors ?? []} />
          </div>
        </section>

        <section className="panel events-panel">
          <div className="panel-title-row">
            <div className="panel-title">Live event feed</div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as Severity | "")}
              className="severity-filter"
            >
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="none">None</option>
            </select>
          </div>
          <EventsTable events={visibleEvents} flashId={flash} onSelect={setSelected} />
        </section>
      </main>

      {selected && <EventDrawer eventId={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
