import { ATTACK_LABEL, DECISION_STYLE } from '../constants'

const BANDS = [
  { from: 0, to: 31, label: 'Safe', color: '#0F7B66' },
  { from: 31, to: 61, label: 'Suspicious', color: '#A8650B' },
  { from: 61, to: 81, label: 'High', color: '#C8531F' },
  { from: 81, to: 100, label: 'Critical', color: '#C8321F' },
]

function RiskMeter({ score }) {
  return (
    <div>
      <div className="relative h-3 flex rounded-sm overflow-hidden" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={score} aria-label="Risk score">
        {BANDS.map((b) => (
          <div key={b.label} style={{ width: `${b.to - b.from + (b.to === 100 ? 0 : 0)}%`, background: b.color, opacity: 0.22 }} />
        ))}
        <div className="absolute inset-y-0 left-0" style={{ width: `${score}%`, background: BANDS.find((b) => score <= b.to)?.color || '#C8321F' }} />
      </div>
      <div className="flex text-[11px] text-ink-mute mt-1">
        {BANDS.map((b) => (
          <div key={b.label} style={{ width: `${b.to - b.from}%` }}>{b.label}</div>
        ))}
      </div>
    </div>
  )
}

export default function Verdict({ r }) {
  const d = DECISION_STYLE[r.decision]
  return (
    <section className={`border-l-4 ${d.border} bg-white border-y border-r border-line rounded-md p-5`} aria-live="polite">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div key={r.id} className={`stamp inline-block text-3xl font-bold tracking-tight ${d.text}`}>{d.label}</div>
          <div className="mt-1 text-sm text-ink-soft">
            {r.attack_type !== 'NONE' ? <>Detected: <strong className="text-ink">{ATTACK_LABEL[r.attack_type]}</strong></> : 'No attack detected'}
            <span className="mx-2 text-line">|</span>
            Decided in {r.latency_ms} ms
          </div>
        </div>
        <div className="text-right">
          <div className="text-4xl font-semibold tabular-nums leading-none">{r.risk_score}<span className="text-lg text-ink-mute"> / 100</span></div>
          <div className="text-xs text-ink-mute mt-1">Risk score, {r.threat_level.toLowerCase()}</div>
        </div>
      </div>

      <div className="mt-4"><RiskMeter score={r.risk_score} /></div>

      <div className="mt-5 grid md:grid-cols-2 gap-6">
        <div>
          <h3 className="text-sm font-semibold">Why this decision</h3>
          <ul className="mt-1.5 space-y-1 text-sm text-ink-soft list-disc pl-4">
            {r.reasons.map((x, i) => <li key={i}>{x}</li>)}
          </ul>
          {r.explanation && <p className="mt-2 text-sm text-ink-soft italic">{r.explanation}</p>}
          <p className={`mt-3 text-sm font-medium ${d.text}`}>{r.recommendation}</p>
        </div>
        <div>
          <h3 className="text-sm font-semibold">Score by detection layer</h3>
          <div className="mt-2 space-y-2">
            {[['Rules', r.scores.rules], ['Semantic similarity', r.scores.semantic], ['LLM classifier', r.scores.llm]].map(([name, v]) => (
              <div key={name} className="flex items-center gap-3 text-sm">
                <span className="w-36 text-ink-soft">{name}</span>
                <div className="flex-1 h-1.5 bg-paper rounded"><div className="h-full bg-ink rounded" style={{ width: `${v ?? 0}%` }} /></div>
                <span className="w-12 text-right tabular-nums text-ink-soft">{v === null ? 'off' : Math.round(v)}</span>
              </div>
            ))}
          </div>
          {r.normalization.techniques.length > 0 && (
            <div className="mt-3 text-xs bg-paper rounded p-2">
              <span className="font-semibold">Unmasked text: </span>
              <span className="font-mono break-words">{r.normalization.normalized}</span>
            </div>
          )}
        </div>
      </div>

      {r.sanitized_prompt && (
        <div className="mt-5 text-sm">
          <h3 className="font-semibold">Sanitized prompt sent to the assistant</h3>
          <p className="mt-1 font-mono text-[13px] bg-sanitize-bg rounded p-2">{r.sanitized_prompt}</p>
        </div>
      )}
      {r.llm_response && (
        <div className="mt-5 text-sm">
          <h3 className="font-semibold">Assistant reply</h3>
          <p className="mt-1 whitespace-pre-wrap text-ink-soft bg-allow-bg rounded p-3">{r.llm_response}</p>
        </div>
      )}
      {r.decision === 'BLOCK' && (
        <p className="mt-5 text-sm text-block bg-block-bg rounded p-3">The request was stopped here. The assistant never received it.</p>
      )}
    </section>
  )
}
