import type { RegulationExposure } from "../types";
import { SeverityBadge } from "./Badges";
import "./ListPanels.css";

export function RegulationList({ data }: { data: RegulationExposure | null }) {
  if (!data || data.regulations.length === 0) {
    return <div className="panel-empty">No regulatory citations in this window.</div>;
  }
  return (
    <ul className="list-panel">
      {data.regulations.slice(0, 10).map((r) => (
        <li key={r.regulation}>
          <span className="list-primary">{r.regulation}</span>
          <span className="list-secondary">{r.events} events</span>
          <SeverityBadge severity={r.max_severity} />
        </li>
      ))}
    </ul>
  );
}
