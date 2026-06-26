import { useEffect, useRef } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { ProtectedRoute } from './components/ProtectedRoute'
import { AdminProtectedRoute } from './components/AdminProtectedRoute'
import { useAuth } from './hooks/useAuth'
import { useAdminAuth } from './hooks/useAdminAuth'
import { HomePage } from './pages/HomePage'
import { LoginPage } from './pages/LoginPage'
import { SignupPage } from './pages/SignupPage'
import { AdminLoginPage } from './pages/admin/AdminLoginPage'
import { AdminUsersPage } from './pages/admin/AdminUsersPage'
import './index.css'

function AppRoutes() {
  const { isInitialized, isAuthenticated, initializeAuth } = useAuth()
  // 관리자 인증도 앱 시작 시 함께 초기화한다.
  // 사용자 refresh(/api/auth/refresh)와 관리자 refresh(/api/admin/auth/refresh)는 서로 다른 엔드포인트이므로
  // 두 요청이 동시에 실행되어도 간섭하지 않는다.
  const { isAdminInitialized, isAdminAuthenticated, initializeAdminAuth } = useAdminAuth()

  // useRef: 리렌더링을 발생시키지 않는 변수. initializeAuth를 한 번만 실행하기 위한 플래그.
  // useState를 쓰면 상태 변경 → 리렌더 → effect 재실행 루프가 생길 수 있다.
  // 참고: React StrictMode는 언마운트 후 remount 시 ref가 초기화되므로,
  //       StrictMode 이중 실행 대응은 client.ts의 refreshAccessToken(single-flight)이 담당한다.
  const initStartedRef = useRef(false)

  useEffect(() => {
    if (initStartedRef.current) {
      return
    }
    initStartedRef.current = true
    // 사용자·관리자 Access Token을 Cookie 기반 silent refresh로 동시에 복구한다.
    initializeAuth()
    initializeAdminAuth()
  }, [initializeAuth, initializeAdminAuth])

  // 사용자·관리자 초기화가 모두 끝나야 라우팅을 시작한다.
  // 쿠키가 없는 쪽은 refresh 실패 → 수십ms 안에 complete되므로 대기 시간이 크게 늘지 않는다.
  if (!isInitialized || !isAdminInitialized) {
    return <p style={{ textAlign: 'center', marginTop: '2rem' }}>인증 상태 확인 중...</p>
  }

  return (
    <Routes>
      {/* ── 사용자 라우트 ── */}
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />}
      />
      <Route
        path="/signup"
        element={isAuthenticated ? <Navigate to="/" replace /> : <SignupPage />}
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <HomePage />
          </ProtectedRoute>
        }
      />

      {/* ── 관리자 라우트 ── */}
      <Route
        path="/admin/login"
        element={isAdminAuthenticated ? <Navigate to="/admin/users" replace /> : <AdminLoginPage />}
      />
      <Route
        path="/admin/users"
        element={
          <AdminProtectedRoute>
            <AdminUsersPage />
          </AdminProtectedRoute>
        }
      />
      {/* /admin 접근 시 /admin/users로 리다이렉트 */}
      <Route path="/admin" element={<Navigate to="/admin/users" replace />} />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  )
}

export default App
