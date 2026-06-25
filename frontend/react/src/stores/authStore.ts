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

// Access Token은 메모리(Zustand)에만 저장 — localStorage/sessionStorage 미사용
export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  user: null,
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
