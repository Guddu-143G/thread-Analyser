import axios from 'axios'

// Support VITE_API_URL or VITE_API_BASE_URL (e.g. https://thread-analyser.vercel.app)
const rawApiUrl = (import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || '').trim()

export const getBaseUrl = () => {
  if (!rawApiUrl) return '/api'
  const trimmed = rawApiUrl.replace(/\/+$/, '')
  return trimmed.endsWith('/api') ? trimmed : `${trimmed}/api`
}

export const API_BASE_URL = getBaseUrl()

export const getApiUrl = (path = '') => {
  const cleanPath = path.startsWith('/') ? path : `/${path}`
  if (cleanPath.startsWith('/api/') || cleanPath === '/api') {
    const sub = cleanPath.replace(/^\/api/, '')
    return `${API_BASE_URL}${sub}`
  }
  return `${API_BASE_URL}${cleanPath}`
}

export const getWsUrl = (path = '/api/ws/stream') => {
  if (import.meta.env.VITE_WS_URL) {
    const wsBase = import.meta.env.VITE_WS_URL.replace(/\/+$/, '')
    const cleanPath = path.startsWith('/') ? path : `/${path}`
    return `${wsBase}${cleanPath}`
  }
  if (rawApiUrl && rawApiUrl.startsWith('http')) {
    const wsBase = rawApiUrl.replace(/^http/, 'ws').replace(/\/+$/, '')
    const cleanPath = path.startsWith('/') ? path : `/${path}`
    return `${wsBase}${cleanPath}`
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host || 'localhost:8000'
  const cleanPath = path.startsWith('/') ? path : `/${path}`
  return `${protocol}//${host}${cleanPath}`
}

// Global interceptor for window.fetch and window.WebSocket when an external backend is configured
export const initApiConfig = () => {
  if (rawApiUrl && rawApiUrl.startsWith('http')) {
    const originalFetch = window.fetch
    window.fetch = function (resource, init) {
      if (typeof resource === 'string' && (resource.startsWith('/api/') || resource === '/api')) {
        resource = getApiUrl(resource)
      }
      return originalFetch.call(this, resource, init)
    }
  }

  const wsBase = import.meta.env.VITE_WS_URL || (rawApiUrl && rawApiUrl.startsWith('http') ? rawApiUrl.replace(/^http/, 'ws') : null)
  if (wsBase) {
    const OriginalWebSocket = window.WebSocket
    window.WebSocket = function (url, protocols) {
      if (typeof url === 'string') {
        try {
          const parsed = new URL(url)
          if (parsed.host === window.location.host || parsed.host === 'localhost:8000') {
            const target = new URL(wsBase)
            parsed.protocol = target.protocol
            parsed.host = target.host
            url = parsed.toString()
          }
        } catch (e) {
          // ignore parsing error and proceed with original url
        }
      }
      return protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url)
    }
    window.WebSocket.prototype = OriginalWebSocket.prototype
  }
}

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 12000,
})


client.interceptors.request.use((config) => {
  if (config.url?.startsWith('/api/')) {
    config.url = config.url.replace(/^\/api/, '')
  }
  const token = localStorage.getItem('ta_token') || localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('ta_token')
      localStorage.removeItem('token')
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

export default client
