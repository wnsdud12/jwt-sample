import axios from 'axios'
import { apiClient, CSRF_HEADER_NAME, CSRF_HEADER_VALUE, refreshAccessToken } from './client'
import type {
  AccessTokenResponse,
  LoginRequest,
  SignupRequest,
  User,
} from '../types/auth'

export async function signup(request: SignupRequest): Promise<User> {
  const response = await apiClient.post<User>('/auth/signup', request)
  return response.data
}

export async function login(request: LoginRequest): Promise<AccessTokenResponse> {
  const response = await apiClient.post<AccessTokenResponse>('/auth/login', request)
  return response.data
}

// refresh/logout은 Cookie 기반이므로 CSRF 방어 커스텀 헤더 필수.
// initializeAuth, 401 인터셉터 모두 client.ts의 refreshAccessToken(single-flight)을 경유한다.
export async function refresh(): Promise<AccessTokenResponse> {
  return refreshAccessToken()
}

export async function logout(): Promise<void> {
  // refresh/logout은 axios 인스턴스(apiClient)를 우회해 직접 호출한다.
  // apiClient의 401 인터셉터가 logout 요청에 걸려 재시도하는 상황을 방지하기 위함이다.
  await axios.post(
    '/api/auth/logout',
    {},
    {
      withCredentials: true,
      headers: {
        [CSRF_HEADER_NAME]: CSRF_HEADER_VALUE,
      },
    },
  )
}

// 401이 나면 apiClient의 응답 인터셉터가 자동으로 refresh → 재시도한다.
export async function getMe(): Promise<User> {
  const response = await apiClient.get<User>('/users/me')
  return response.data
}
