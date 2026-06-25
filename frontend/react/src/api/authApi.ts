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

// refresh/logout은 Cookie 기반이므로 CSRF 방어 커스텀 헤더 필수
// initializeAuth, 401 인터셉터 모두 client.ts의 refreshAccessToken(single-flight)을 경유
export async function refresh(): Promise<AccessTokenResponse> {
  return refreshAccessToken()
}

export async function logout(): Promise<void> {
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

export async function getMe(): Promise<User> {
  const response = await apiClient.get<User>('/users/me')
  return response.data
}
