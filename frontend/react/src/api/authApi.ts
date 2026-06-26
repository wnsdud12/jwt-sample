import axios from 'axios'
import { useMutation } from '@tanstack/react-query'
import { apiClient, CSRF_HEADER_NAME, CSRF_HEADER_VALUE, refreshAccessToken } from './client'
import type { AccessTokenResponse, LoginRequest, SignupRequest, User } from '../types/auth'

// --- signup ---
const postSignup = async (body: SignupRequest): Promise<User> => {
  const { data } = await apiClient.post<User>('/auth/signup', body)
  return data
}
export const useSignup = () => useMutation({ mutationFn: postSignup })

// --- login ---
const postLogin = async (body: LoginRequest): Promise<AccessTokenResponse> => {
  const { data } = await apiClient.post<AccessTokenResponse>('/auth/login', body)
  return data
}
export const useLogin = () => useMutation({ mutationFn: postLogin })

// --- refresh ---
// initializeAuth, 401 인터셉터 모두 client.ts의 refreshAccessToken(single-flight)을 경유한다.
// postRefresh는 useAuth의 initializeAuth에서도 직접 호출하므로 export한다.
export const postRefresh = async (): Promise<AccessTokenResponse> => refreshAccessToken()
export const useRefresh = () => useMutation({ mutationFn: postRefresh })

// --- logout ---
// refresh/logout은 Cookie 기반이므로 CSRF 방어 커스텀 헤더 필수.
// apiClient를 우회해 직접 호출하는 이유: apiClient의 401 인터셉터가 logout 요청에 걸려 재시도하는 상황 방지.
const postLogout = async (): Promise<void> => {
  await axios.post('/api/auth/logout', {}, {
    withCredentials: true,
    headers: {
      [CSRF_HEADER_NAME]: CSRF_HEADER_VALUE,
    },
  })
}
export const useLogout = () => useMutation({ mutationFn: postLogout })

// --- getMe ---
// 항상 login/refresh 직후 순서로 호출되므로 useQuery 대신 plain function으로 제공한다.
// 401이 나면 apiClient의 응답 인터셉터가 자동으로 refresh → 재시도한다.
export const getMe = async (): Promise<User> => {
  const { data } = await apiClient.get<User>('/users/me')
  return data
}
