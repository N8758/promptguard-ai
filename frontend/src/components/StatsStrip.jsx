export default function StatsStrip({ stats }) {
  const items = [
    { label: 'Requests screened', value: stats?.total_requests ?? '–' },
    { label: 'Threats detected', value: stats?.threats_detected ?? '–' },
    { label: 'Blocked', value: stats?.blocked ?? '–' },
    { label: 'Avg. decision time', value: stats ? `${stats.avg_latency_ms} ms` : '–' },
    { label: 'Security score', value: stats ? `${stats.security_score}%` : '–', hint: 'Share of risky requests that were blocked or sanitized' },
  ]
  return (
    <dl className="grid grid-cols-2 sm:grid-cols-5 border border-line bg-white rounded-md divide-x divide-line">
      {items.map((s) => (
        <div key={s.label} className="px-4 py-3" title={s.hint}>
          <dt className="text-xs text-ink-mute">{s.label}</dt>
          <dd className="mt-0.5 text-2xl font-semibold tabular-nums">{s.value}</dd>
        </div>
      ))}
    </dl>
  )
}
