import { PRESETS } from '../constants'

export default function PromptConsole({ prompt, setPrompt, onAnalyze, loading }) {
  return (
    <section className="bg-white border border-line rounded-md p-4">
      <label htmlFor="prompt" className="text-sm font-semibold">Test a prompt</label>
      <p className="text-sm text-ink-soft mt-0.5">Whatever you type goes through the firewall before it can reach the AI assistant.</p>
      <textarea
        id="prompt"
        value={prompt}
        onChange={(e) => setPrompt(e.target.value)}
        onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') onAnalyze() }}
        rows={4}
        placeholder="Type a message a user might send to your banking assistant..."
        className="mt-3 w-full font-mono text-[13px] leading-relaxed bg-paper/60 border border-line rounded p-3 focus:bg-white focus:border-ink resize-y"
      />
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          onClick={onAnalyze}
          disabled={loading || !prompt.trim()}
          className="bg-ink text-white text-sm font-semibold px-4 py-2 rounded hover:bg-ink-soft disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {loading ? 'Analyzing…' : 'Analyze prompt'}
        </button>
        <span className="text-xs text-ink-mute mr-2">Ctrl + Enter</span>
        <div className="flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              onClick={() => setPrompt(p.prompt)}
              className="text-xs px-2.5 py-1 rounded-full border border-line bg-white text-ink-soft hover:border-ink hover:text-ink"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>
    </section>
  )
}
