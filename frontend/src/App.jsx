import { useCallback, useEffect, useState } from 'react'
import { analyzePrompt, getHealth, getHistory, getStats, seedDemo } from './api'
import StatsStrip from './components/StatsStrip'
import PromptConsole from './components/PromptConsole'
import Verdict from './components/Verdict'
import AgentPipeline from './components/AgentPipeline'
import ThreatChart from './components/ThreatChart'
import History from './components/History'

export default function App() {
  const [prompt, setPrompt] = useState('')
  const [result, setResult] = useState(null)
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    try {
      const [s, h] = await Promise.all([getStats(), getHistory(12)])
      setStats(s); setHistory(h); setError('')
    } catch {
      setError('Cannot reach the PromptGuard API. Start the backend (uvicorn app.main:app --reload --port 8000) and check VITE_API_BASE_URL in frontend/.env.')
    }
  }, [])

  useEffect(() => { refresh(); getHealth().then(setHealth).catch(() => {}) }, [refresh])

  const analyze = async () => {
    if (!prompt.trim() || loading) return
    setLoading(true)
    try {
      setResult(await analyzePrompt(prompt))
      await refresh()
    } catch (e) {
      setError(e.response?.data?.detail || 'The analysis failed. Check the backend logs.')
    } finally { setLoading(false) }
  }

  const loadDemo = async () => { setLoading(true); try { await seedDemo(); await refresh() } finally { setLoading(false) } }

  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-white">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 3l11 4v8c0 7-4.6 11.5-11 14C9.6 26.5 5 22 5 15V7z" fill="#0E1A2B" /><path d="M11 16l4 4 7-8" stroke="#fff" strokeWidth="3" fill="none" /></svg>
            <div>
              <h1 className="text-lg font-bold leading-none">PromptGuard AI</h1>
              <p className="text-xs text-ink-mute mt-0.5">Prompt injection firewall for AI agents</p>
            </div>
          </div>
          <div className="text-xs text-ink-soft flex items-center gap-3">
            {health ? (
              <>
                <span><span className="inline-block w-2 h-2 rounded-full bg-allow mr-1.5 align-middle" />Protected</span>
                <span className="hidden sm:inline">LLM: {health.llm}</span>
                <span className="hidden sm:inline">Storage: {health.storage}</span>
                <span className="hidden md:inline">Similarity: {health.semantic_engine}</span>
              </>
            ) : <span><span className="inline-block w-2 h-2 rounded-full bg-block mr-1.5 align-middle" />API offline</span>}
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-5 space-y-5">
        {error && <div role="alert" className="text-sm bg-block-bg text-block border border-block/30 rounded p-3">{error}</div>}
        <StatsStrip stats={stats} />

        <div className="grid lg:grid-cols-5 gap-5">
          <div className="lg:col-span-3 space-y-5">
            <PromptConsole prompt={prompt} setPrompt={setPrompt} onAnalyze={analyze} loading={loading} />
            {result ? (
              <>
                <Verdict r={result} />
                <AgentPipeline agents={result.agents} resultId={result.id} />
              </>
            ) : (
              <div className="bg-white border border-dashed border-line rounded-md p-8 text-center text-sm text-ink-soft">
                Pick an example above or write your own prompt, then choose <strong>Analyze prompt</strong> to see the firewall decide.
              </div>
            )}
          </div>
          <div className="lg:col-span-2 space-y-5">
            <ThreatChart data={stats?.threats_by_type} />
            <History rows={history} onPick={setPrompt} />
            {stats && stats.total_requests === 0 && (
              <button onClick={loadDemo} className="w-full text-sm border border-ink rounded py-2 hover:bg-ink hover:text-white">Load sample traffic into the dashboard</button>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}
