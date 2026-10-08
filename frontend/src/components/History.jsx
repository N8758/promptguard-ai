import { ATTACK_LABEL, DECISION_STYLE } from '../constants'

export default function History({ rows, onPick }) {
  return (
    <section className="bg-white border border-line rounded-md p-4">
      <h2 className="text-sm font-semibold">Recent requests</h2>
      {rows.length === 0 ? (
        <p className="text-sm text-ink-mute mt-3">Nothing screened yet.</p>
      ) : (
        <div className="mt-2 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-ink-mute border-b border-line">
                <th className="py-1.5 pr-3 font-medium">Prompt</th>
                <th className="py-1.5 pr-3 font-medium">Type</th>
                <th className="py-1.5 pr-3 font-medium text-right">Risk</th>
                <th className="py-1.5 font-medium">Decision</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const d = DECISION_STYLE[r.decision]
                return (
                  <tr key={r.id} className="border-b border-line/60 last:border-0 hover:bg-paper/60 cursor-pointer" onClick={() => onPick(r.prompt_text)}>
                    <td className="py-1.5 pr-3 max-w-[260px] truncate font-mono text-[12px]" title={r.prompt_text}>{r.prompt_text}</td>
                    <td className="py-1.5 pr-3 text-ink-soft whitespace-nowrap">{ATTACK_LABEL[r.attack_type]}</td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{r.risk_score}</td>
                    <td className="py-1.5"><span className={`text-xs font-medium px-2 py-0.5 rounded ${d.bg} ${d.text}`}>{d.label}</span></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
