import { Navigate, useLocation } from 'react-router-dom'
import { useAdminAuth } from '../hooks/useAdminAuth'

interface AdminProtectedRouteProps {
  children: React.ReactNode
}

// 관리자 인증 상태를 확인하는 라우트 래퍼 컴포넌트.
// ProtectedRoute와 동일한 구조이지만 useAdminAuth를 사용한다.
export function AdminProtectedRoute({ children }: AdminProtectedRouteProps) {
  const { isAdminAuthenticated, isAdminInitialized } = useAdminAuth()
  const location = useLocation()

  if (!isAdminInitialized) {
    return <p>인증 상태 확인 중...</p>
  }

  if (!isAdminAuthenticated) {
    return <Navigate to="/admin/login" state={{ from: location }} replace />
  }

  return children
}
