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
  // 같은 마운트 안에서 useEffect가 재실행될 때 initializeAuth 중복 호출 방지 (보조 수단)
  // 참고: StrictMode는 언마운트 후 remount 시 ref가 초기화되므로, StrictMode 대응은 client.ts의 refreshAccessToken(single-flight)이 담당
  const initStartedRef = useRef(false)

  useEffect(() => {
    if (initStartedRef.current) {
      return
    }
    initStartedRef.current = true
    // 앱 시작/새로고침 시 Cookie 기반 silent refresh → Access Token을 메모리에 복구
    initializeAuth()
  }, [initializeAuth])

  if (!isInitialized) {
    return <p style={{ textAlign: 'center', marginTop: '2rem' }}>인증 상태 확인 중...</p>
  }

  return (
    <Routes>
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
