import { formatDistanceToNow } from "date-fns";
import type { EventOut } from "../types";
import { ActionBadge, SeverityBadge } from "./Badges";
import "./EventsTable.css";

interface Props {
  events: EventOut[];
  flashId: string | null;
  onSelect: (id: string) => void;
}

export function EventsTable({ events, flashId, onSelect }: Props) {
  if (events.length === 0) {
    return <div className="events-empty">No events match the current filters.</div>;
  }
  return (
    <div className="events-table-wrap">
      <table className="events-table">
        <thead>
          <tr>
            <th>When</th>
            <th>Severity</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Source</th>
            <th>Score</th>
            <th>Council</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {[...events]
            .sort((a, b) => b.created_at.localeCompare(a.created_at))
            .map((e) => (
              <tr
                key={e.id}
                className={
                  (e.id === flashId ? "row-flash " : "") +
                  (e.retro_escalated ? "row-escalated " : "") +
                  (!e.acknowledged_at && e.severity === "critical" ? "row-open-critical" : "")
                }
                onClick={() => onSelect(e.id)}
              >
                <td className="cell-time" title={e.created_at}>
                  {formatDistanceToNow(new Date(e.created_at), { addSuffix: true })}
                </td>
                <td>
                  <SeverityBadge severity={e.severity} />
                </td>
                <td>
                  <ActionBadge action={e.action} />
                  {e.retro_escalated && <span className="escalated-tag">retro</span>}
                </td>
                <td className="cell-actor">
                  {e.actor || <span className="muted">unattributed</span>}
                  {e.actor_department && <span className="dept"> · {e.actor_department}</span>}
                </td>
                <td className="cell-source">
                  {e.source}
                  {e.provider && <span className="muted"> → {e.provider}</span>}
                </td>
                <td className="cell-score">{e.risk_score}</td>
                <td className="cell-council">
                  <span className={`council-pill council-${e.council_status}`}>
                    {e.council_status}
                  </span>
                </td>
                <td className="cell-reason">{e.action_reason || "—"}</td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}
