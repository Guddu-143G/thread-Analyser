import React, { useState } from 'react'

export const SecurePasswordInput = ({
  label = "Password",
  value,
  onChange,
  placeholder = "••••••••••••",
  autocompleteType = "current-password",
  required = true,
  disabled = false,
  id = "secure-password-input",
  name = "password"
}) => {
  const [showPassword, setShowPassword] = useState(false)

  const toggleVisibility = (e) => {
    e.preventDefault() // Prevent form submit
    e.stopPropagation()
    setShowPassword((prev) => !prev)
  }

  return (
    <div className="flex flex-col w-full space-y-1.5">
      {label && (
        <label htmlFor={id} className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
          {label}
        </label>
      )}

      <div className="relative flex items-center w-full">
        {/* Visual Lock Accent Icon */}
        <span className="absolute left-3 text-slate-500 select-none flex items-center justify-center pointer-events-none">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </span>

        {/* Dynamic Type HTML Input Element */}
        <input
          id={id}
          name={name}
          type={showPassword ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete={autocompleteType}
          required={required}
          disabled={disabled}
          className="w-full pl-10 pr-12 py-2.5 bg-base-950 border border-base-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-slate-100 rounded-md outline-none transition-all duration-150 font-mono text-sm placeholder-slate-600 disabled:opacity-50"
        />

        {/* Interactive Show/Hide Toggle Control Button */}
        <button
          type="button"
          onClick={toggleVisibility}
          tabIndex={0}
          aria-label={showPassword ? "Hide password" : "Show password"}
          className="absolute right-3 p-1.5 hover:bg-base-800 rounded-full text-slate-500 hover:text-cyan-400 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 focus:ring-offset-base-950 select-none"
        >
          {showPassword ? (
            /* EyeOff Icon */
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18" />
            </svg>
          ) : (
            /* Eye Icon */
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
            </svg>
          )}
        </button>
      </div>
    </div>
  )
}

export default SecurePasswordInput
