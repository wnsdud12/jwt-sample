import axios from 'axios'
import type { AxiosError, InternalAxiosRequestConfig } from 'axios'
import { useAuthStore } from '../stores/authStore'
import type { AccessTokenResponse } from '../types/auth'

// Cookie 기반 refresh/logout CSRF 방어용 커스텀 헤더
export const CSRF_HEADER_NAME = 'X-Requested-With'
export const CSRF_HEADER_VALUE = 'XMLHttpRequest'

// 모든 API 요청에 공통 설정을 적용하는 axios 인스턴스.
export const apiClient = axios.create({
  baseURL: '/api',
  // withCredentials: true — Cookie를 요청에 포함시킨다.
  // Vite 개발 서버가 /api를 Spring Boot로 프록시하므로 same-origin처럼 동작하지만,
  // 운영 환경(프론트엔드와 API 서버가 다른 도메인)에서도 Cookie가 전송되도록 미리 설정한다.
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 요청 인터셉터: 모든 API 요청에 Access Token을 자동으로 첨부한다.
// 컴포넌트마다 직접 Authorization 헤더를 추가할 필요가 없다.
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const accessToken = useAuthStore.getState().accessToken
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }
  return config
})

// Single-flight 패턴: 동시에 여러 곳에서 refresh를 호출해도 실제 네트워크 요청은 1번만 보낸다.
// 이미 진행 중인 Promise가 있으면 새 요청을 만들지 않고 같은 Promise를 공유한다.
//
// 필요한 이유:
//   - React StrictMode: 개발 모드에서 useEffect가 두 번 실행될 수 있다.
//   - initializeAuth(앱 시작 시 refresh) + 401 인터셉터(만료된 토큰으로 API 호출)가 동시에 실행될 수 있다.
// Rotation 방식 서버에서 동시에 2개의 refresh 요청이 가면 첫 번째가 토큰을 교체한 뒤
// 두 번째가 "이전 토큰 재사용"으로 감지되어 모든 Refresh Token이 무효화될 수 있다.
//
// TanStack Query의 useMutation은 중복 요청을 자동으로 막지 않는다(useQuery와 다름).
// authApi.ts의 postRefresh, 401 인터셉터가 모두 이 함수를 경유하므로
// useMutation 인스턴스가 몇 개든 네트워크 요청은 이 single-flight가 1번으로 수렴시킨다.
let refreshPromise: Promise<AccessTokenResponse> | null = null

export function refreshAccessToken(): Promise<AccessTokenResponse> {
  if (refreshPromise) {
    // 이미 진행 중인 refresh가 있으면 같은 Promise를 반환한다.
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
      // 완료 후 초기화 → 이후 refresh는 새 Promise로 처리한다.
      refreshPromise = null
    })

  return refreshPromise
}

// 응답 인터셉터: 401 응답을 받으면 refresh를 1회 시도하고 원 요청을 재전송한다.
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }

    if (error.response?.status !== 401 || !originalRequest || originalRequest._retry) {
      return Promise.reject(error)
    }

    // 로그인·refresh 자체가 401이면 재시도 없이 원본 에러를 그대로 반환한다.
    // 재시도하면 refresh 실패 에러가 원본 에러를 덮어써서 잘못된 메시지가 표시된다.
    if (originalRequest.url?.includes('/auth/refresh') || originalRequest.url?.includes('/auth/login')) {
      useAuthStore.getState().clearAuth()
      return Promise.reject(error)
    }

    // _retry 플래그로 재시도를 1회로 제한한다. 없으면 401 → refresh → 401 → ... 무한 루프가 생긴다.
    originalRequest._retry = true

    try {
      // 401 인터셉터도 동일한 refreshAccessToken을 사용 → initializeAuth와 요청이 합쳐짐 (single-flight)
      const tokenResponse = await refreshAccessToken()
      originalRequest.headers.Authorization = `Bearer ${tokenResponse.accessToken}`
      return apiClient(originalRequest)
    } catch (refreshError) {
      useAuthStore.getState().clearAuth()
      return Promise.reject(refreshError)
    }
  },
)
