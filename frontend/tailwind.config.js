/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: {
          950: '#0a0e14',
          900: '#0f141b',
          800: '#161c26',
          700: '#1f2733',
          600: '#2a3441',
        },
        accent: {
          DEFAULT: '#00d4a0',
          dim: '#0a9e77',
        },
        severity: {
          low: '#3b82f6',
          medium: '#eab308',
          high: '#f97316',
          critical: '#ef4444',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
