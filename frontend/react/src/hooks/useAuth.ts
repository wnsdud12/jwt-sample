import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useLogin, useSignup, useLogout, postRefresh, getMe } from '../api/authApi'
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

  const { mutateAsync: loginMutate } = useLogin()
  const { mutateAsync: signupMutate } = useSignup()
  const { mutateAsync: logoutMutate } = useLogout()

  // 앱 최초 로드·새로고침 시 Cookie의 Refresh Token으로 Access Token을 복구한다(silent refresh).
  // user-triggered 액션이 아니라 앱 초기화 흐름이므로 useMutation 대신 plain function을 직접 호출한다.
  const initializeAuth = useCallback(async () => {
    try {
      const tokenData = await postRefresh()
      setAccessToken(tokenData.accessToken)
      const userData = await getMe()
      setUser(userData)
    } catch {
      // Cookie 없음·만료 등 실패 시 로그아웃 상태로 유지한다.
      clearAuth()
    } finally {
      // 성공·실패 모두 isInitialized를 true로 설정해 ProtectedRoute가 결과를 알 수 있게 한다.
      setInitialized(true)
    }
  }, [setAccessToken, setUser, setInitialized, clearAuth])

  const login = useCallback(
    async (request: LoginRequest) => {
      const tokenData = await loginMutate(request)
      setAccessToken(tokenData.accessToken)
      const userData = await getMe()
      setUser(userData)
      navigate('/')
    },
    [loginMutate, setAccessToken, setUser, navigate],
  )

  const signup = useCallback(
    async (request: SignupRequest) => {
      await signupMutate(request)
      navigate('/login')
    },
    [signupMutate, navigate],
  )

  const logout = useCallback(async () => {
    try {
      await logoutMutate()
    } finally {
      // 서버 요청이 실패해도(네트워크 오류 등) 로컬 상태는 항상 초기화한다.
      clearAuth()
      navigate('/login')
    }
  }, [logoutMutate, clearAuth, navigate])

  // accessToken과 user 둘 다 있어야 인증된 상태로 본다.
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
