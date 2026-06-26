import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAdminLogin, useAdminLogout, postAdminRefresh } from '../api/adminAuthApi'
import { useAdminAuthStore } from '../stores/adminAuthStore'
import type { LoginRequest } from '../types/auth'

// 관리자 인증 상태와 액션을 제공하는 커스텀 훅.
// 사용자 useAuth와 완전히 분리되어 있어 동일한 브라우저에서 사용자·관리자를 동시에 유지할 수 있다.
export function useAdminAuth() {
  const navigate = useNavigate()
  const adminAccessToken = useAdminAuthStore((state) => state.adminAccessToken)
  const isAdminInitialized = useAdminAuthStore((state) => state.isAdminInitialized)
  const setAdminAccessToken = useAdminAuthStore((state) => state.setAdminAccessToken)
  const setAdminInitialized = useAdminAuthStore((state) => state.setAdminInitialized)
  const clearAdminAuth = useAdminAuthStore((state) => state.clearAdminAuth)

  const { mutateAsync: adminLoginMutate } = useAdminLogin()
  const { mutateAsync: adminLogoutMutate } = useAdminLogout()

  // 앱 최초 로드 시 admin_refresh_token 쿠키로 관리자 Access Token을 복구한다.
  // 쿠키가 없거나 만료된 경우 조용히 clearAdminAuth()로 처리하며 오류를 던지지 않는다.
  const initializeAdminAuth = useCallback(async () => {
    try {
      const tokenData = await postAdminRefresh()
      setAdminAccessToken(tokenData.accessToken)
    } catch {
      clearAdminAuth()
    } finally {
      setAdminInitialized(true)
    }
  }, [setAdminAccessToken, setAdminInitialized, clearAdminAuth])

  const adminLogin = useCallback(
    async (request: LoginRequest) => {
      const tokenData = await adminLoginMutate(request)
      setAdminAccessToken(tokenData.accessToken)
      navigate('/admin/users')
    },
    [adminLoginMutate, setAdminAccessToken, navigate],
  )

  const adminLogout = useCallback(async () => {
    try {
      await adminLogoutMutate()
    } finally {
      clearAdminAuth()
      navigate('/admin/login')
    }
  }, [adminLogoutMutate, clearAdminAuth, navigate])

  const isAdminAuthenticated = adminAccessToken !== null

  return {
    adminAccessToken,
    isAdminInitialized,
    isAdminAuthenticated,
    initializeAdminAuth,
    adminLogin,
    adminLogout,
  }
}
