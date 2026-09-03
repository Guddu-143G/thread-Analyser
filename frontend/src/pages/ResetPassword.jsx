import React, { useState, useEffect } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import api from '../api/client'
import SecurePasswordInput from '../components/SecurePasswordInput'

export default function ResetPassword() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const token = searchParams.get('token') || ''

  const [validating, setValidating] = useState(true)
  const [tokenValid, setTokenValid] = useState(false)
  const [userEmail, setUserEmail] = useState('')
  const [validationError, setValidationError] = useState('')

  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [submitError, setSubmitError] = useState('')
  const [success, setSuccess] = useState(false)
  const [loading, setLoading] = useState(false)

  // Validate token on mount
  useEffect(() => {
    if (!token) {
      setValidating(false)
      setTokenValid(false)
      setValidationError('No reset token provided in the URL.')
      return
    }

    const checkToken = async () => {
      try {
        const res = await api.get(`/auth/validate-reset-token?token=${encodeURIComponent(token)}`)
        if (res.data.valid) {
          setTokenValid(true)
          setUserEmail(res.data.email || '')
        } else {
          setTokenValid(false)
          setValidationError(res.data.message || 'Token is invalid or expired.')
        }
      } catch (err) {
        setTokenValid(false)
        setValidationError(err.response?.data?.detail || 'Failed to validate reset token.')
      } finally {
        setValidating(false)
      }
    }

    checkToken()
  }, [token])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitError('')

    if (password.length < 8) {
      setSubmitError('Password must be at least 8 characters long.')
      return
    }

    if (password !== confirmPassword) {
      setSubmitError('Passwords do not match.')
      return
    }

    setLoading(true)
    try {
      await api.post('/auth/reset-password', {
        token,
        new_password: password
      })
      setSuccess(true)
    } catch (err) {
      setSubmitError(err.response?.data?.detail || 'Failed to reset password. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 bg-base-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-2xl mb-3 shadow-lg shadow-emerald-500/10">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="font-mono text-xl font-bold tracking-wider text-slate-100">SET NEW PASSWORD</h1>
          <p className="text-slate-500 text-xs mt-1">Enterprise Argon2 / Bcrypt Cryptographic Update</p>
        </div>

        <div className="panel p-6 space-y-5 shadow-2xl border border-base-800 bg-base-900/90 backdrop-blur">
          {validating && (
            <div className="text-center py-6">
              <div className="inline-block w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
              <p className="font-mono text-xs text-slate-400 mt-3">Verifying cryptographic token signature...</p>
            </div>
          )}

          {!validating && !tokenValid && (
            <div className="space-y-4">
              <div className="text-xs p-4 rounded-lg bg-severity-critical/10 border border-severity-critical/30 text-severity-critical font-mono">
                <p className="font-bold">Invalid or Expired Token</p>
                <p className="mt-1 text-slate-400">{validationError}</p>
              </div>
              <Link
                to="/forgot-password"
                className="block text-center py-2 px-4 rounded bg-base-800 hover:bg-base-700 text-slate-200 font-mono text-xs transition-colors"
              >
                Request a New Reset Link
              </Link>
            </div>
          )}

          {!validating && tokenValid && success && (
            <div className="space-y-4">
              <div className="text-xs p-4 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 font-mono">
                <p className="font-bold text-sm">Password Successfully Reset!</p>
                <p className="mt-1 text-slate-300">
                  All prior active sessions have been invalidated. You can now log in securely with your new password.
                </p>
              </div>
              <button
                type="button"
                onClick={() => navigate('/login')}
                className="w-full py-2.5 px-4 rounded-md font-mono text-xs font-semibold tracking-wider uppercase transition-all duration-150 bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 text-slate-950 shadow-lg shadow-emerald-500/20"
              >
                Proceed to Sign In →
              </button>
            </div>
          )}

          {!validating && tokenValid && !success && (
            <form onSubmit={handleSubmit} className="space-y-4">
              {submitError && (
                <div className="text-xs p-3 rounded bg-severity-critical/10 border border-severity-critical/30 text-severity-critical font-mono">
                  {submitError}
                </div>
              )}

              {userEmail && (
                <div className="bg-base-950 px-3 py-2 rounded border border-base-800 text-xs font-mono text-slate-400 flex items-center justify-between">
                  <span>Account:</span>
                  <span className="text-slate-200 font-semibold">{userEmail}</span>
                </div>
              )}

              <div>
                <SecurePasswordInput
                  id="new-password"
                  label="New Password"
                  value={password}
                  onChange={setPassword}
                  autocompleteType="new-password"
                  placeholder="Minimum 8 characters"
                />
              </div>

              <div>
                <SecurePasswordInput
                  id="confirm-password"
                  label="Confirm New Password"
                  value={confirmPassword}
                  onChange={setConfirmPassword}
                  autocompleteType="new-password"
                  placeholder="Repeat new password"
                />
              </div>

              <div className="bg-base-950/60 p-3 rounded border border-base-800 text-[11px] text-slate-400 font-mono">
                <span className="text-emerald-400 font-bold">Session Security:</span> Submitting this form invalidates all existing OAuth & Bearer JWT sessions across all devices.
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 rounded-md font-mono text-xs font-semibold tracking-wider uppercase transition-all duration-150 bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 text-slate-950 shadow-lg shadow-emerald-500/20 disabled:opacity-50"
              >
                {loading ? 'Updating Password…' : 'Confirm Password Change'}
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
