import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../api/client'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [status, setStatus] = useState({ type: '', message: '', devLink: '', devToken: '' })
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setStatus({ type: '', message: '', devLink: '', devToken: '' })
    setLoading(true)

    try {
      const res = await api.post('/auth/forgot-password', { email })
      setStatus({
        type: 'success',
        message: res.data.message || 'If the account exists, a secure password reset link has been dispatched.',
        devLink: res.data.dev_reset_link,
        devToken: res.data.dev_token_preview
      })
    } catch (err) {
      setStatus({
        type: 'error',
        message: err.response?.data?.detail || 'Failed to dispatch password recovery link. Please try again.',
        devLink: '',
        devToken: ''
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-base-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 text-2xl mb-3 shadow-lg shadow-amber-500/10">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
          </div>
          <h1 className="font-mono text-xl font-bold tracking-wider text-slate-100">ACCOUNT RECOVERY</h1>
          <p className="text-slate-500 text-xs mt-1">Cryptographic 15-Minute Token Reset Pipeline</p>
        </div>

        <div className="panel p-6 space-y-5 shadow-2xl border border-base-800 bg-base-900/90 backdrop-blur">
          {status.message && (
            <div
              className={`text-xs p-3.5 rounded-lg border font-mono ${
                status.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                  : 'bg-severity-critical/10 border-severity-critical/30 text-severity-critical'
              }`}
            >
              <div className="flex items-start gap-2">
                <span className="text-sm font-bold">{status.type === 'success' ? '✓' : '⚠'}</span>
                <div>
                  <p className="font-semibold">{status.message}</p>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Standard 15-minute expiration applies. SHA-256 hashed at rest.
                  </p>
                </div>
              </div>

              {/* Dev/Demo Quick Link */}
              {status.devLink && (
                <div className="mt-3 pt-3 border-t border-emerald-500/20">
                  <span className="text-[10px] uppercase font-bold text-amber-400 tracking-wider">
                    Demo Mode Instant Dispatch Link:
                  </span>
                  <div className="mt-1.5 flex items-center gap-2">
                    <Link
                      to={status.devLink}
                      className="px-3 py-1.5 rounded bg-emerald-500 text-slate-950 font-bold text-xs hover:bg-emerald-400 transition-colors inline-block"
                    >
                      Click to Open Reset Form →
                    </Link>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1 truncate">
                    Token: <span className="font-mono text-slate-400">{status.devToken}</span>
                  </p>
                </div>
              )}
            </div>
          )}

          {!status.devLink && (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono mb-1.5">
                  Registered Work Email
                </label>
                <input
                  type="email"
                  required
                  autoComplete="email"
                  className="w-full px-3 py-2.5 bg-base-950 border border-base-700 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 text-slate-100 rounded-md outline-none transition-all duration-150 font-mono text-sm placeholder-slate-600"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@soc-corp.internal"
                />
              </div>

              <div className="bg-base-950/60 p-3 rounded border border-base-800 text-[11px] text-slate-400 font-mono">
                <span className="text-amber-400 font-bold">Security Note:</span> To prevent account enumeration attacks, confirmation is delivered generically without exposing registered directory status.
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 rounded-md font-mono text-xs font-semibold tracking-wider uppercase transition-all duration-150 bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-slate-950 shadow-lg shadow-amber-500/20 disabled:opacity-50"
              >
                {loading ? 'Generating Token…' : 'Send Recovery Link'}
              </button>
            </form>
          )}

          <div className="pt-2 text-center border-t border-base-800/80">
            <Link to="/login" className="text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors">
              ← Return to Login
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
