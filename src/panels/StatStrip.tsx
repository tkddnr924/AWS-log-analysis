/// One run's numbers, shown on the parse-completion screen. The results
/// screen used to carry the same strip; it was removed because the rule list
/// beside it already states every count.
export type Stat = {
  label: string;
  value: number;
  unit?: string;
  /// Only the outcomes worth acting on are coloured.
  tone?: "warn" | "danger";
};

export function StatStrip({ stats }: { stats: Stat[] }) {
  return (
    <dl className="stats">
      {stats.map((s) => (
        <div key={s.label} className={s.tone ? `stat t-${s.tone}` : "stat"}>
          <dt>{s.label}</dt>
          <dd>
            {s.value.toLocaleString()}
            {s.unit && <span className="stat-unit">{s.unit}</span>}
          </dd>
        </div>
      ))}
    </dl>
  );
}
