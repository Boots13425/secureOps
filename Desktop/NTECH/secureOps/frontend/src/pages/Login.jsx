import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ShieldCheck, Mail, Lock, Eye, EyeOff } from 'lucide-react'

export default function Login() {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')

  function handleSubmit(e) {
    e.preventDefault()
    if (!email || !password) {
      setError('Enter both an email and a password.')
      return
    }
    // No real backend yet — accept any non-empty email/password.
    setError('')
    navigate('/')
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--bg-page)] px-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center gap-2.5 mb-8">
          <div className="flex items-center justify-center w-11 h-11 rounded-[var(--radius-sm)] bg-[var(--accent)] text-white">
            <ShieldCheck size={22} strokeWidth={2.2} />
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-[var(--text-primary)] leading-tight">SecureOps Hub</div>
            <div className="text-xs text-[var(--text-muted)] leading-tight">IT Security Platform</div>
          </div>
        </div>

        <div className="card">
          <h1 className="text-lg font-semibold text-[var(--text-primary)] mb-1">Sign in</h1>
          <p className="text-sm text-[var(--text-muted)] mb-6">Enter your credentials to access your dashboard</p>

          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            {error && (
              <div className="text-xs text-[var(--danger-text)] bg-[var(--danger-bg)] border border-[var(--danger)] rounded-[var(--radius-sm)] px-3 py-2">
                {error}
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1.5" htmlFor="email">
                Email
              </label>
              <div className="relative">
                <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] pl-9 pr-3 py-2.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none focus:border-[var(--accent)]"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-xs font-medium text-[var(--text-secondary)]" htmlFor="password">
                  Password
                </label>
                <a href="#" className="text-xs text-[var(--accent)] hover:underline">
                  Forgot password?
                </a>
              </div>
              <div className="relative">
                <Lock size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-[var(--bg-surface-2)] border border-[var(--border)] rounded-[var(--radius-sm)] pl-9 pr-9 py-2.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none focus:border-[var(--accent)]"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="mt-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-sm font-medium px-4 py-2.5 rounded-[var(--radius-sm)] transition-colors"
            >
              Sign in
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-[var(--text-muted)] mt-5">
          Don&apos;t have an account?{' '}
          <Link to="/signup" className="text-[var(--accent)] hover:underline">
            Sign up
          </Link>
        </p>
      </div>
    </div>
  )
}
