import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import SecurePasswordInput from '../components/SecurePasswordInput'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-base-950">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-2xl mb-3 shadow-lg shadow-cyan-500/10">
            ◆
          </div>
          <h1 className="font-mono text-xl font-bold tracking-wider text-slate-100">THREAT ANALYSER</h1>
          <p className="text-slate-500 text-xs mt-1">Enterprise SOC Multi-Tenant Console</p>
          <div className="mt-2 inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-cyan-950/60 text-cyan-400 border border-cyan-800/50">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
            Neon Auth & Authorize RLS Enabled
          </div>
        </div>

        <form onSubmit={handleSubmit} className="panel p-6 space-y-4 shadow-2xl border border-base-800 bg-base-900/90 backdrop-blur">
          {error && (
            <div className="text-sm text-severity-critical bg-severity-critical/10 border border-severity-critical/30 rounded-md px-3 py-2">
              {error}
            </div>
          )}
          
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono mb-1.5">
              Work Email
            </label>
            <input
              type="email"
              required
              autoComplete="email"
              className="w-full px-3 py-2.5 bg-base-950 border border-base-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-slate-100 rounded-md outline-none transition-all duration-150 font-mono text-sm placeholder-slate-600"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@soc-corp.internal"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
                Password
              </span>
              <Link to="/forgot-password" className="text-xs text-cyan-400 hover:text-cyan-300 font-mono transition-colors">
                Forgot password?
              </Link>
            </div>
            <SecurePasswordInput
              label=""
              value={password}
              onChange={setPassword}
              autocompleteType="current-password"
              placeholder="••••••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-md font-mono text-xs font-semibold tracking-wider uppercase transition-all duration-150 bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-slate-950 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            {loading ? 'Authenticating…' : 'Sign in to Console'}
          </button>
        </form>

        <p className="text-center text-xs text-slate-500 mt-5 font-mono">
          No tenant account? <Link to="/register" className="text-cyan-400 hover:underline">Register Organization</Link>
        </p>
      </div>
    </div>
  )
}
