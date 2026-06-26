import { create } from 'zustand'

interface AdminAuthState {
  adminAccessToken: string | null
  isAdminInitialized: boolean
  setAdminAccessToken: (token: string) => void
  setAdminInitialized: (value: boolean) => void
  clearAdminAuth: () => void
}

// 관리자 전용 인증 상태 스토어.
// 사용자 authStore와 완전히 분리되어 있어 한 브라우저에서 사용자/관리자를 동시에 로그인해도 충돌하지 않는다.
// 관리자 Access Token도 메모리에만 저장한다(사용자와 동일한 이유).
export const useAdminAuthStore = create<AdminAuthState>((set) => ({
  adminAccessToken: null,
  isAdminInitialized: false,
  setAdminAccessToken: (adminAccessToken) => set({ adminAccessToken }),
  setAdminInitialized: (isAdminInitialized) => set({ isAdminInitialized }),
  clearAdminAuth: () => set({ adminAccessToken: null }),
}))
