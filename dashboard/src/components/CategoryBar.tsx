import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Category, Summary } from "../types";
import { CATEGORY_LABELS } from "./Badges";
import "./Charts.css";

const CATEGORY_COLOR: Record<Category, string> = {
  pii: "var(--series-1)",
  phi: "var(--series-2)",
  pci: "var(--series-3)",
  secret: "var(--series-4)",
  ip: "var(--series-5)",
  regulated: "var(--series-6)",
  other: "var(--series-7)",
};

function TooltipContent({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-row">
        <span className="chart-tooltip-swatch" style={{ background: p.color }} />
        <span className="chart-tooltip-label">{p.label}</span>
        <span className="chart-tooltip-value">{p.value} events</span>
      </div>
    </div>
  );
}

export function CategoryBar({ data }: { data: Summary["by_category"] | null }) {
  if (!data) return <div className="chart-empty">Loading…</div>;
  const rows = (Object.entries(data) as [Category, number][])
    .filter(([, v]) => v > 0)
    .map(([category, value]) => ({
      category,
      label: CATEGORY_LABELS[category],
      value,
      color: CATEGORY_COLOR[category],
    }))
    .sort((a, b) => b.value - a.value);

  if (rows.length === 0) return <div className="chart-empty">No findings in this window.</div>;

  return (
    <ResponsiveContainer width="100%" height={Math.max(140, rows.length * 34)}>
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 20, left: 0, bottom: 4 }}>
        <XAxis type="number" hide allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="label"
          width={90}
          tickLine={false}
          axisLine={false}
          tick={{ fill: "var(--text-secondary)", fontSize: 12 }}
        />
        <Tooltip content={<TooltipContent />} cursor={{ fill: "var(--surface-2)" }} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} maxBarSize={18}>
          {rows.map((r) => (
            <Cell key={r.category} fill={r.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
