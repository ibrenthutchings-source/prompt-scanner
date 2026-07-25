import "./StatTile.css";

interface Props {
  label: string;
  value: string | number;
  delta?: number | null;
  tone?: "default" | "good" | "warning" | "serious" | "critical";
  sublabel?: string;
}

export function StatTile({ label, value, delta, tone = "default", sublabel }: Props) {
  return (
    <div className={`stat-tile tone-${tone}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {(delta !== undefined && delta !== null) || sublabel ? (
        <div className="stat-sub">
          {delta !== undefined && delta !== null && (
            <span className={delta >= 0 ? "delta-up" : "delta-down"}>
              {delta >= 0 ? "▲" : "▼"} {Math.abs(delta).toFixed(1)}%
            </span>
          )}
          {sublabel && <span className="stat-sublabel">{sublabel}</span>}
        </div>
      ) : null}
    </div>
  );
}
