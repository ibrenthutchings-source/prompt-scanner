import type { Summary } from "../types";
import "./ListPanels.css";

export function TopDetectors({ data }: { data: Summary["top_detectors"] }) {
  if (data.length === 0) return <div className="panel-empty">No detector hits yet.</div>;
  return (
    <ul className="list-panel">
      {data.map((d) => (
        <li key={d.detector}>
          <span className="list-primary">{d.title}</span>
          <span className="list-secondary mono">{d.detector}</span>
          <span className="list-count">{d.count}</span>
        </li>
      ))}
    </ul>
  );
}

export function TopActors({ data }: { data: Summary["top_actors"] }) {
  if (data.length === 0) return <div className="panel-empty">No attributable activity yet.</div>;
  return (
    <ul className="list-panel">
      {data.map((a) => (
        <li key={a.actor}>
          <span className="list-primary">{a.actor}</span>
          <span className="list-secondary">
            {a.department || "—"} · max risk {a.max_score}
            {a.blocked > 0 ? ` · ${a.blocked} blocked` : ""}
          </span>
          <span className="list-count">{a.events}</span>
        </li>
      ))}
    </ul>
  );
}
