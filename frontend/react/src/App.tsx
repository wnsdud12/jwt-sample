import { useEffect, useRef } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { ProtectedRoute } from './components/ProtectedRoute'
import { useAuth } from './hooks/useAuth'
import { HomePage } from './pages/HomePage'
import { LoginPage } from './pages/LoginPage'
import { SignupPage } from './pages/SignupPage'
import './index.css'

function AppRoutes() {
  const { isInitialized, isAuthenticated, initializeAuth } = useAuth()

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
    // 앱 시작·새로고침 시 Cookie 기반 silent refresh로 Access Token을 메모리에 복구한다.
    initializeAuth()
  }, [initializeAuth])

  // initializeAuth가 끝나기 전에는 라우팅을 시작하지 않는다.
  // 무조건 렌더링하면 정상 로그인 상태인데도 로그인 페이지로 튕기는 문제가 생긴다.
  if (!isInitialized) {
    return <p style={{ textAlign: 'center', marginTop: '2rem' }}>인증 상태 확인 중...</p>
  }

  return (
    <Routes>
      {/* 이미 로그인된 상태면 /login, /signup 접근 시 홈으로 리다이렉트 */}
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />}
      />
      <Route
        path="/signup"
        element={isAuthenticated ? <Navigate to="/" replace /> : <SignupPage />}
      />
      {/* ProtectedRoute: 로그인하지 않은 사용자가 접근하면 /login으로 리다이렉트 */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <HomePage />
          </ProtectedRoute>
        }
      />
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
