import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ATTACK_LABEL } from '../constants'

export default function ThreatChart({ data }) {
  const rows = (data || []).map((d) => ({ name: ATTACK_LABEL[d.attack_type] || d.attack_type, total: Number(d.total) }))
  return (
    <section className="bg-white border border-line rounded-md p-4">
      <h2 className="text-sm font-semibold">Threats by type</h2>
      {rows.length === 0 ? (
        <p className="text-sm text-ink-mute mt-3">No threats yet. Run an attack from the prompt tester.</p>
      ) : (
        <div className="h-52 mt-2">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rows} layout="vertical" margin={{ left: 0, right: 16, top: 4, bottom: 0 }}>
              <XAxis type="number" allowDecimals={false} hide />
              <YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 12, fill: '#44546A' }} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: '#EDF0F3' }} contentStyle={{ fontSize: 12, borderRadius: 4, border: '1px solid #D5DBE3' }} />
              <Bar dataKey="total" radius={[0, 3, 3, 0]} barSize={16} label={{ position: 'right', fontSize: 12, fill: '#0E1A2B' }}>
                {rows.map((_, i) => <Cell key={i} fill="#0E1A2B" />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  )
}
