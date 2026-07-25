import type { Action, Category, Severity } from "../types";
import "./Badges.css";

// Status color always ships with an icon + label — never hue alone.
const SEVERITY_META: Record<Severity, { css: string; icon: string; label: string }> = {
  none: { css: "sev-none", icon: "○", label: "None" },
  low: { css: "sev-low", icon: "●", label: "Low" },
  medium: { css: "sev-medium", icon: "▲", label: "Medium" },
  high: { css: "sev-high", icon: "▲", label: "High" },
  critical: { css: "sev-critical", icon: "■", label: "Critical" },
};

const ACTION_META: Record<Action, { css: string; icon: string; label: string }> = {
  allow: { css: "sev-none", icon: "✓", label: "Allowed" },
  warn: { css: "sev-medium", icon: "▲", label: "Warned" },
  redact: { css: "sev-high", icon: "▤", label: "Redacted" },
  block: { css: "sev-critical", icon: "✕", label: "Blocked" },
};

const CATEGORY_LABEL: Record<Category, string> = {
  pii: "PII",
  phi: "PHI",
  pci: "PCI",
  secret: "Secret",
  ip: "IP",
  regulated: "Regulated use",
  other: "Other",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const m = SEVERITY_META[severity];
  return (
    <span className={`badge ${m.css}`}>
      <span aria-hidden="true">{m.icon}</span> {m.label}
    </span>
  );
}

export function ActionBadge({ action }: { action: Action }) {
  const m = ACTION_META[action];
  return (
    <span className={`badge ${m.css}`}>
      <span aria-hidden="true">{m.icon}</span> {m.label}
    </span>
  );
}

export function CategoryChip({ category }: { category: Category }) {
  return <span className={`chip chip-${category}`}>{CATEGORY_LABEL[category]}</span>;
}

export const CATEGORY_LABELS = CATEGORY_LABEL;
