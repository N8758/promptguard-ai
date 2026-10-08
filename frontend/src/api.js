import axios from 'axios'

const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000', timeout: 60000 })

export const analyzePrompt = (prompt, forward_to_llm = true) => api.post('/api/analyze', { prompt, forward_to_llm }).then((r) => r.data)
export const getStats = () => api.get('/api/stats').then((r) => r.data)
export const getHistory = (limit = 12) => api.get('/api/history', { params: { limit } }).then((r) => r.data)
export const getHealth = () => api.get('/api/health').then((r) => r.data)
export const seedDemo = () => api.post('/api/demo/seed').then((r) => r.data)
