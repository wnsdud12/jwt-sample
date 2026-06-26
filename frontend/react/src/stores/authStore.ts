import { create } from 'zustand'
import type { User } from '../types/auth'

interface AuthState {
  accessToken: string | null
  user: User | null
  isInitialized: boolean
  setAccessToken: (accessToken: string) => void
  setUser: (user: User) => void
  setInitialized: (isInitialized: boolean) => void
  clearAuth: () => void
}

// Zustand 전역 상태 스토어: 인증 관련 상태를 앱 어디서든 구독·변경할 수 있다.
//
// Access Token을 메모리에만 저장하는 이유:
//   - localStorage / sessionStorage: XSS로 악성 스크립트가 직접 읽을 수 있어 토큰 탈취 위험.
//   - HttpOnly Cookie: JavaScript 접근 불가로 안전하지만, Access Token을 Cookie에 담으면 CSRF 위험이 생긴다.
//   - 메모리(Zustand): 페이지 새로고침 시 사라지지만, HttpOnly Cookie의 Refresh Token으로 복구한다(silent refresh).
export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  user: null,
  // isInitialized: 앱 시작 시 silent refresh 시도가 끝났는지 여부.
  // false인 동안은 ProtectedRoute가 인증 상태를 알 수 없으므로 로딩 화면을 보여준다.
  isInitialized: false,
  setAccessToken: (accessToken) => {
    set({ accessToken })
  },
  setUser: (user) => {
    set({ user })
  },
  setInitialized: (isInitialized) => {
    set({ isInitialized })
  },
  clearAuth: () => {
    set({ accessToken: null, user: null })
  },
}))
