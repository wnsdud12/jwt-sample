import axios from 'axios'
import type { AxiosError, InternalAxiosRequestConfig } from 'axios'
import { useAdminAuthStore } from '../stores/adminAuthStore'
import type { AccessTokenResponse } from '../types/auth'

// Cookie 기반 refresh/logout CSRF 방어용 커스텀 헤더 (사용자 client.ts와 동일한 방식)
export const ADMIN_CSRF_HEADER_NAME = 'X-Requested-With'
export const ADMIN_CSRF_HEADER_VALUE = 'XMLHttpRequest'

// 관리자 전용 axios 인스턴스. 사용자 apiClient와 완전히 분리되어 있다.
// baseURL이 /api/admin이므로 '내부에서 쓰는 경로'는 /auth/login 처럼 앞부분을 생략한다.
export const adminApiClient = axios.create({
  baseURL: '/api/admin',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 요청 인터셉터: 관리자 Access Token을 자동으로 첨부한다.
adminApiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const adminAccessToken = useAdminAuthStore.getState().adminAccessToken
  if (adminAccessToken) {
    config.headers.Authorization = `Bearer ${adminAccessToken}`
  }
  return config
})

// Single-flight 패턴: 관리자 refresh도 동시에 여러 번 호출되면 1번만 실제 요청을 보낸다.
// 사용자 refreshPromise와 완전히 별개이므로 두 refreshPromise가 동시에 진행되어도 간섭하지 않는다.
let adminRefreshPromise: Promise<AccessTokenResponse> | null = null

export function refreshAdminAccessToken(): Promise<AccessTokenResponse> {
  if (adminRefreshPromise) {
    return adminRefreshPromise
  }

  // /api/admin/auth/refresh 엔드포인트를 직접 호출한다.
  // 브라우저는 path=/api/admin/auth인 admin_refresh_token 쿠키를 이 요청에 자동으로 첨부한다.
  adminRefreshPromise = axios
    .post<AccessTokenResponse>(
      '/api/admin/auth/refresh',
      {},
      {
        withCredentials: true,
        headers: {
          [ADMIN_CSRF_HEADER_NAME]: ADMIN_CSRF_HEADER_VALUE,
        },
      },
    )
    .then((response) => {
      useAdminAuthStore.getState().setAdminAccessToken(response.data.accessToken)
      return response.data
    })
    .finally(() => {
      adminRefreshPromise = null
    })

  return adminRefreshPromise
}

// 응답 인터셉터: 401 시 refresh 1회 시도 후 원 요청을 재전송한다.
adminApiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

    if (error.response?.status !== 401 || !originalRequest || originalRequest._retry) {
      return Promise.reject(error)
    }

    // 로그인·refresh 자체가 401이면 재시도 없이 원본 에러를 그대로 반환한다.
    // 재시도하면 refresh 실패 에러가 원본 에러를 덮어써서 잘못된 메시지가 표시된다.
    if (originalRequest.url?.includes('/auth/refresh') || originalRequest.url?.includes('/auth/login')) {
      useAdminAuthStore.getState().clearAdminAuth()
      return Promise.reject(error)
    }

    originalRequest._retry = true

    try {
      const tokenResponse = await refreshAdminAccessToken()
      originalRequest.headers.Authorization = `Bearer ${tokenResponse.accessToken}`
      return adminApiClient(originalRequest)
    } catch (refreshError) {
      useAdminAuthStore.getState().clearAdminAuth()
      return Promise.reject(refreshError)
    }
  },
)
