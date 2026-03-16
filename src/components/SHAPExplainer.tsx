import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts'
import { SHAPValue } from '../types'

interface SHAPExplainerProps {
  data: SHAPValue[]
  title: string
}

export default function SHAPExplainer({ data, title }: SHAPExplainerProps) {
  if (!data || data.length === 0) return null

  // Sort by absolute SHAP value for better visualization
  const sortedData = [...data].sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value))

  return (
    <div className="shap-explainer">
      <h4 style={{ fontSize: '0.85rem', marginBottom: '12px', color: 'var(--text-secondary)' }}>
        {title}
      </h4>
      <div style={{ height: '220px', width: '100%' }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={sortedData}
            layout="vertical"
            margin={{ top: 5, right: 30, left: 100, bottom: 5 }}
          >
            <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="rgba(255,255,255,0.05)" />
            <XAxis type="number" hide />
            <YAxis 
              dataKey="feature" 
              type="category" 
              width={90}
              tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
            />
            <Tooltip
              contentStyle={{ backgroundColor: '#111827', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px' }}
              itemStyle={{ color: '#e8eaf6', fontSize: '11px' }}
              formatter={(value: number) => [value.toFixed(4), 'SHAP Value']}
            />
            <Bar dataKey="shap_value" radius={[0, 4, 4, 0]}>
              {sortedData.map((entry, index) => (
                <Cell 
                  key={`cell-${index}`} 
                  fill={entry.shap_value > 0 ? 'var(--accent-red)' : 'var(--accent-cyan)'} 
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '8px' }}>
        Red bars increase threat probability, green bars decrease it.
      </p>
    </div>
  )
}
