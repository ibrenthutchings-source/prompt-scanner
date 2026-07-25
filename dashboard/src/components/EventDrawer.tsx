import { useEffect, useState } from "react";
import { api } from "../api";
import type { CouncilDetail, EventDetailOut } from "../types";
import { ActionBadge, CategoryChip, SeverityBadge } from "./Badges";
import "./EventDrawer.css";

export function EventDrawer({ eventId, onClose }: { eventId: string; onClose: () => void }) {
  const [event, setEvent] = useState<EventDetailOut | null>(null);
  const [council, setCouncil] = useState<CouncilDetail | null>(null);
  const [ackBy, setAckBy] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setEvent(null);
    setCouncil(null);
    api
      .event(eventId)
      .then((e) => !cancelled && setEvent(e))
      .catch((e) => !cancelled && setError(String(e)));
    api
      .council(eventId)
      .then((c) => !cancelled && setCouncil(c))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [eventId]);

  async function acknowledge() {
    if (!ackBy.trim()) return;
    setBusy(true);
    try {
      const updated = await api.acknowledge(eventId, ackBy.trim(), note.trim() || undefined);
      setEvent((prev) => (prev ? { ...prev, ...updated } : prev));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" onClick={(e) => e.stopPropagation()}>
        <div className="drawer-header">
          <div>
            <div className="drawer-title">Event {eventId.slice(0, 12)}</div>
            {event && (
              <div className="drawer-meta">
                {new Date(event.created_at).toLocaleString()} · {event.source}
                {event.provider ? ` → ${event.provider}` : ""}
              </div>
            )}
          </div>
          <button className="drawer-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        {error && <div className="drawer-error">{error}</div>}
        {!event ? (
          <div className="drawer-loading">Loading…</div>
        ) : (
          <div className="drawer-body">
            <div className="drawer-badges">
              <SeverityBadge severity={event.severity} />
              <ActionBadge action={event.action} />
              <span className="score-pill">risk {event.risk_score}</span>
              {event.retro_escalated && (
                <span className="escalated-pill">retroactively escalated</span>
              )}
            </div>

            <Section title="Why">
              <p className="reason-text">{event.action_reason || "—"}</p>
              {event.council_summary && (
                <p className="council-summary">{event.council_summary}</p>
              )}
            </Section>

            <Section title="Context">
              <dl className="kv">
                <dt>Actor</dt>
                <dd>
                  {event.actor || "unattributed"}
                  {event.actor_department ? ` (${event.actor_department})` : ""}
                </dd>
                <dt>Client</dt>
                <dd>{event.client_app || "—"}</dd>
                <dt>Destination model</dt>
                <dd>{event.model || "—"}</dd>
                <dt>Prompt size</dt>
                <dd>{event.prompt_chars.toLocaleString()} chars</dd>
                <dt>Fast gate</dt>
                <dd>{event.fast_gate_ms.toFixed(2)} ms</dd>
                {event.council_ms > 0 && (
                  <>
                    <dt>Council</dt>
                    <dd>
                      {event.council_ms.toFixed(0)} ms · ${event.council_cost_usd.toFixed(4)}
                    </dd>
                  </>
                )}
              </dl>
            </Section>

            <Section title={`Findings (${event.findings.length})`}>
              {event.findings.length === 0 ? (
                <p className="empty-note">No findings recorded.</p>
              ) : (
                <ul className="findings-list">
                  {[...event.findings]
                    .sort((a, b) => b.score - a.score)
                    .map((f) => (
                      <li key={f.id} className="finding">
                        <div className="finding-head">
                          <CategoryChip category={f.category} />
                          <SeverityBadge severity={f.severity} />
                          <span className="finding-stage">
                            {f.stage === "council" ? "council" : "detector"}
                          </span>
                          <span className="finding-title">{f.title}</span>
                        </div>
                        {f.detail && <p className="finding-detail">{f.detail}</p>}
                        {f.evidence && <code className="finding-evidence">{f.evidence}</code>}
                        {f.regulations.length > 0 && (
                          <div className="finding-regs">
                            {f.regulations.map((r) => (
                              <span key={r} className="reg-tag">
                                {r}
                              </span>
                            ))}
                          </div>
                        )}
                      </li>
                    ))}
                </ul>
              )}
            </Section>

            {council && council.votes.length > 0 && (
              <Section title="Council deliberation">
                <ul className="votes-list">
                  {council.votes.map((v) => (
                    <li key={v.agent} className={`vote ${v.agent === "adjudicator" ? "vote-adjudicator" : ""}`}>
                      <div className="vote-head">
                        <span className="vote-agent">
                          {v.agent === "adjudicator" ? "Adjudicator (final verdict)" : formatAgent(v.agent)}
                        </span>
                        {!v.error && <SeverityBadge severity={v.severity} />}
                        <span className="vote-latency">{v.latency_ms.toFixed(0)} ms</span>
                      </div>
                      {v.error ? (
                        <p className="vote-error">Unavailable: {v.error}</p>
                      ) : (
                        <p className="vote-rationale">{v.rationale}</p>
                      )}
                    </li>
                  ))}
                </ul>
              </Section>
            )}

            <Section title="Acknowledge">
              {event.acknowledged_by ? (
                <p className="ack-status">
                  Acknowledged by <strong>{event.acknowledged_by}</strong>
                  {event.acknowledged_at &&
                    ` on ${new Date(event.acknowledged_at).toLocaleString()}`}
                  {event.analyst_note && <span className="ack-note"> — {event.analyst_note}</span>}
                </p>
              ) : (
                <div className="ack-form">
                  <input
                    placeholder="Your name"
                    value={ackBy}
                    onChange={(e) => setAckBy(e.target.value)}
                  />
                  <input
                    placeholder="Note (optional)"
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                  <button disabled={busy || !ackBy.trim()} onClick={acknowledge}>
                    {busy ? "Saving…" : "Acknowledge"}
                  </button>
                </div>
              )}
            </Section>
          </div>
        )}
      </aside>
    </div>
  );
}

function formatAgent(key: string): string {
  return key
    .split("_")
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(" ");
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="drawer-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}
