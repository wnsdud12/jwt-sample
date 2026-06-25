import axios from 'axios'
import type { AxiosError, InternalAxiosRequestConfig } from 'axios'
import { useAuthStore } from '../stores/authStore'
import type { AccessTokenResponse } from '../types/auth'

// Cookie 기반 refresh/logout CSRF 방어용 커스텀 헤더
export const CSRF_HEADER_NAME = 'X-Requested-With'
export const CSRF_HEADER_VALUE = 'XMLHttpRequest'

export const apiClient = axios.create({
  baseURL: '/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Bearer Access Token 자동 첨부
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const accessToken = useAuthStore.getState().accessToken
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }
  return config
})

// Refresh Token Rotation 환경에서는 동시에 refresh가 2번 나가면
// 첫 요청이 토큰을 교체한 뒤 두 번째 요청이 "재사용"으로 판단될 수 있음
// (React StrictMode 이중 effect, initializeAuth + 401 인터셉터 겹침, 연속 F5 등)
// → 진행 중인 refresh Promise를 공유해 네트워크 요청을 1번만 보냄 (single-flight)
let refreshPromise: Promise<AccessTokenResponse> | null = null

export function refreshAccessToken(): Promise<AccessTokenResponse> {
  if (refreshPromise) {
    return refreshPromise
  }

  refreshPromise = axios
    .post<AccessTokenResponse>(
      '/api/auth/refresh',
      {},
      {
        withCredentials: true,
        headers: {
          [CSRF_HEADER_NAME]: CSRF_HEADER_VALUE,
        },
      },
    )
    .then((response) => {
      useAuthStore.getState().setAccessToken(response.data.accessToken)
      return response.data
    })
    .finally(() => {
      // 완료 후 초기화 → 이후 refresh는 새 Promise로 처리
      refreshPromise = null
    })

  return refreshPromise
}

// 401 응답 시 refresh 1회 시도 후 원 요청 재시도
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

    if (error.response?.status !== 401 || !originalRequest || originalRequest._retry) {
      return Promise.reject(error)
    }

    if (originalRequest.url?.includes('/auth/refresh')) {
      useAuthStore.getState().clearAuth()
      return Promise.reject(error)
    }

    originalRequest._retry = true

    try {
      // 401 인터셉터도 동일한 refreshAccessToken을 사용 → initializeAuth와 요청이 합쳐짐
      const tokenResponse = await refreshAccessToken()
      originalRequest.headers.Authorization = `Bearer ${tokenResponse.accessToken}`
      return apiClient(originalRequest)
    } catch (refreshError) {
      useAuthStore.getState().clearAuth()
      return Promise.reject(refreshError)
    }
  },
)
