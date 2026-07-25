import { format } from "date-fns";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Timeseries } from "../types";
import "./Charts.css";

// Action severity, one axis, stacked so the total reads as "prompts scanned"
// and the composition reads as "how they were handled". Status colors carry
// the action's meaning (never a generic categorical hue for allow/warn/etc).
const SERIES: { key: keyof Timeseries["series"][number]; label: string; color: string }[] = [
  { key: "allow", label: "Allowed", color: "var(--status-good)" },
  { key: "warn", label: "Warned", color: "var(--status-warning)" },
  { key: "redact", label: "Redacted", color: "var(--status-serious)" },
  { key: "block", label: "Blocked", color: "var(--status-critical)" },
];

function fmtTick(iso: string) {
  return format(new Date(iso), "HH:mm");
}

function TooltipContent({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-title">{format(new Date(label), "MMM d, HH:mm")}</div>
      {payload
        .slice()
        .reverse()
        .map((p: any) => (
          <div key={p.dataKey} className="chart-tooltip-row">
            <span className="chart-tooltip-swatch" style={{ background: p.color }} />
            <span className="chart-tooltip-label">{p.name}</span>
            <span className="chart-tooltip-value">{p.value}</span>
          </div>
        ))}
    </div>
  );
}

export function ActivityChart({ data }: { data: Timeseries | null }) {
  if (!data || data.series.length === 0) {
    return <div className="chart-empty">No activity in this window.</div>;
  }
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={data.series} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <CartesianGrid stroke="var(--gridline)" vertical={false} />
        <XAxis
          dataKey="t"
          tickFormatter={fmtTick}
          stroke="var(--axis)"
          tick={{ fill: "var(--text-muted)", fontSize: 11 }}
          axisLine={{ stroke: "var(--axis)" }}
          tickLine={false}
          minTickGap={40}
        />
        <YAxis
          allowDecimals={false}
          stroke="var(--axis)"
          tick={{ fill: "var(--text-muted)", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={30}
        />
        <Tooltip content={<TooltipContent />} cursor={{ stroke: "var(--axis)", strokeWidth: 1 }} />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: 12, color: "var(--text-secondary)" }}
        />
        {SERIES.map((s) => (
          <Area
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.label}
            stackId="1"
            stroke={s.color}
            fill={s.color}
            fillOpacity={0.28}
            strokeWidth={2}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}
