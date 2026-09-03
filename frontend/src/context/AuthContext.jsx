import { createContext, useContext, useEffect, useState, useCallback } from 'react'
import client from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const loadUser = useCallback(async () => {
    const token = localStorage.getItem('ta_token')
    if (!token) {
      setLoading(false)
      return
    }
    try {
      const { data } = await client.get('/auth/me')
      setUser(data)
    } catch {
      localStorage.removeItem('ta_token')
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadUser()
  }, [loadUser])

  const login = async (email, password) => {
    const { data } = await client.post('/auth/login', { email, password })
    localStorage.setItem('ta_token', data.access_token)
    await loadUser()
  }

  const register = async (org_name, email, password) => {
    const { data } = await client.post('/auth/register', { org_name, email, password })
    localStorage.setItem('ta_token', data.access_token)
    await loadUser()
  }

  const logout = () => {
    localStorage.removeItem('ta_token')
    setUser(null)
    window.location.href = '/login'
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
