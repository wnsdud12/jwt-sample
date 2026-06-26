import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import * as authApi from '../api/authApi'
import { useAuthStore } from '../stores/authStore'
import type { LoginRequest, SignupRequest } from '../types/auth'

// 인증 관련 상태와 액션을 한 곳에서 제공하는 커스텀 훅.
// 컴포넌트는 authStore나 authApi를 직접 사용하지 않고 이 훅을 통해 인증을 처리한다.
export function useAuth() {
  const navigate = useNavigate()
  const accessToken = useAuthStore((state) => state.accessToken)
  const user = useAuthStore((state) => state.user)
  const isInitialized = useAuthStore((state) => state.isInitialized)
  const setAccessToken = useAuthStore((state) => state.setAccessToken)
  const setUser = useAuthStore((state) => state.setUser)
  const setInitialized = useAuthStore((state) => state.setInitialized)
  const clearAuth = useAuthStore((state) => state.clearAuth)

  // 앱 최초 로드·새로고침 시 Cookie의 Refresh Token으로 Access Token을 복구한다(silent refresh).
  // Access Token은 메모리에만 있어 새로고침 시 사라지기 때문에 이 과정이 필요하다.
  // 실패하면(Cookie 없음·만료) 로그아웃 상태로 유지하고,
  // finally에서 setInitialized(true)를 호출해 ProtectedRoute가 결과를 알 수 있게 한다.
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
      // 로그인 성공 후 getMe로 사용자 정보도 가져와 상태에 저장한다.
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
      // 서버 요청이 실패해도(네트워크 오류 등) 로컬 상태는 항상 초기화한다.
      // 서버에서 Cookie를 삭제하지 못했더라도 클라이언트에서는 로그아웃 처리를 완료한다.
      clearAuth()
      navigate('/login')
    }
  }, [clearAuth, navigate])

  // accessToken과 user 둘 다 있어야 인증된 상태로 본다.
  // initializeAuth가 완료되기 전에는 accessToken이 없어 항상 false다.
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
