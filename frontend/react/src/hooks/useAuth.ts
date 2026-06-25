import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import * as authApi from '../api/authApi'
import { useAuthStore } from '../stores/authStore'
import type { LoginRequest, SignupRequest } from '../types/auth'

export function useAuth() {
  const navigate = useNavigate()
  const accessToken = useAuthStore((state) => state.accessToken)
  const user = useAuthStore((state) => state.user)
  const isInitialized = useAuthStore((state) => state.isInitialized)
  const setAccessToken = useAuthStore((state) => state.setAccessToken)
  const setUser = useAuthStore((state) => state.setUser)
  const setInitialized = useAuthStore((state) => state.setInitialized)
  const clearAuth = useAuthStore((state) => state.clearAuth)

  const initializeAuth = useCallback(async () => {
    try {
      const tokenResponse = await authApi.refresh()
      setAccessToken(tokenResponse.accessToken)
      const userResponse = await authApi.getMe()
      setUser(userResponse)
    } catch {
      clearAuth()
    } finally {
      setInitialized(true)
    }
  }, [setAccessToken, setUser, setInitialized, clearAuth])

  const login = useCallback(
    async (request: LoginRequest) => {
      const tokenResponse = await authApi.login(request)
      setAccessToken(tokenResponse.accessToken)
      const userResponse = await authApi.getMe()
      setUser(userResponse)
      navigate('/')
    },
    [setAccessToken, setUser, navigate],
  )

  const signup = useCallback(
    async (request: SignupRequest) => {
      await authApi.signup(request)
      navigate('/login')
    },
    [navigate],
  )

  const logout = useCallback(async () => {
    try {
      await authApi.logout()
    } finally {
      clearAuth()
      navigate('/login')
    }
  }, [clearAuth, navigate])

  const isAuthenticated = accessToken !== null && user !== null

  return {
    accessToken,
    user,
    isInitialized,
    isAuthenticated,
    initializeAuth,
    login,
    signup,
    logout,
  }
}
