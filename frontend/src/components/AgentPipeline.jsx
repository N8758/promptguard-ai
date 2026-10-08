import { useEffect, useState } from 'react'
import { AGENT_INFO } from '../constants'

export default function AgentPipeline({ agents, resultId }) {
  const [shown, setShown] = useState(0)
  const [open, setOpen] = useState(null)

  useEffect(() => {
    setShown(0); setOpen(null)
    const timers = agents.map((_, i) => setTimeout(() => setShown(i + 1), 140 * (i + 1)))
    return () => timers.forEach(clearTimeout)
  }, [resultId])

  return (
    <section className="bg-white border border-line rounded-md p-4">
      <h2 className="text-sm font-semibold">How the five security agents handled it</h2>
      <ol className="mt-3 grid grid-cols-1 md:grid-cols-5 gap-2">
        {agents.map((a, i) => {
          const info = AGENT_INFO[a.name]
          const visible = i < shown
          const isOpen = open === a.name
          return (
            <li key={a.name} className={visible ? 'reveal' : 'opacity-0'}>
              <button
                onClick={() => setOpen(isOpen ? null : a.name)}
                aria-expanded={isOpen}
                className={`w-full text-left h-full border rounded p-3 hover:border-ink ${isOpen ? 'border-ink bg-paper/60' : 'border-line'}`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold">{info.title}</span>
                  <span className="text-[11px] text-allow font-medium">✓ {a.duration_ms} ms</span>
                </div>
                <div className="text-xs text-ink-mute mt-0.5">{info.question}</div>
                <div className="text-xs text-ink-soft mt-2 leading-snug">{a.summary}</div>
              </button>
            </li>
          )
        })}
      </ol>
      {open && (
        <pre className="mt-3 text-[12px] font-mono bg-ink text-paper rounded p-3 overflow-x-auto max-h-72">
          {JSON.stringify(agents.find((a) => a.name === open)?.output, null, 2)}
        </pre>
      )}
      <p className="text-xs text-ink-mute mt-2">Select an agent to see exactly what it returned.</p>
    </section>
  )
}
