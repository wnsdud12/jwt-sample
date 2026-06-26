import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

interface ProtectedRouteProps {
  children: React.ReactNode
}

// 로그인한 사용자만 접근할 수 있는 라우트 래퍼 컴포넌트.
export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isInitialized } = useAuth()
  const location = useLocation()

  // initializeAuth(silent refresh)가 끝나기 전에는 인증 상태를 알 수 없다.
  // 바로 판단하면 정상 로그인 상태인데도 /login으로 튕기는 문제가 생기므로, 완료될 때까지 기다린다.
  if (!isInitialized) {
    return <p>인증 상태 확인 중...</p>
  }

  if (!isAuthenticated) {
    // state.from: 로그인 후 원래 가려던 페이지로 돌아가기 위해 현재 경로를 전달한다.
    // (이 샘플에서는 LoginPage가 state.from을 활용하지 않지만, 확장 시 사용 가능)
    // TODO: 추후 state.from을 사용한 예시 추가 예정
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return children
}
