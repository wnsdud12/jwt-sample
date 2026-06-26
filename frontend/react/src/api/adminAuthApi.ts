import axios from 'axios'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  adminApiClient,
  ADMIN_CSRF_HEADER_NAME,
  ADMIN_CSRF_HEADER_VALUE,
  refreshAdminAccessToken,
} from './adminClient'
import type { AccessTokenResponse, LoginRequest, User } from '../types/auth'

// --- adminLogin ---
const postAdminLogin = async (body: LoginRequest): Promise<AccessTokenResponse> => {
  const { data } = await adminApiClient.post<AccessTokenResponse>('/auth/login', body)
  return data
}
export const useAdminLogin = () => useMutation({ mutationFn: postAdminLogin })

// --- adminRefresh ---
// initializeAdminAuth에서 직접 호출하므로 plain function도 export한다.
export const postAdminRefresh = async (): Promise<AccessTokenResponse> =>
  refreshAdminAccessToken()
export const useAdminRefresh = () => useMutation({ mutationFn: postAdminRefresh })

// --- adminLogout ---
// logout은 adminApiClient의 401 인터셉터가 불필요하게 작동하지 않도록 raw axios로 호출한다.
const postAdminLogout = async (): Promise<void> => {
  await axios.post('/api/admin/auth/logout', {}, {
    withCredentials: true,
    headers: {
      [ADMIN_CSRF_HEADER_NAME]: ADMIN_CSRF_HEADER_VALUE,
    },
  })
}
export const useAdminLogout = () => useMutation({ mutationFn: postAdminLogout })

// --- getUsers ---
// useQuery로 감싸서 훅 형태로 제공한다.
// queryKey: TanStack Query가 캐시를 구분하는 키. ['admin', 'users']로 네임스페이스를 분리한다.
const fetchUsers = async (): Promise<User[]> => {
  const { data } = await adminApiClient.get<User[]>('/users')
  return data
}
export const useUsers = () =>
  useQuery({
    queryKey: ['admin', 'users'],
    queryFn: fetchUsers,
  })
