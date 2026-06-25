import { useAuth } from '../hooks/useAuth'
import './AuthPages.css'

export function HomePage() {
  const { user, logout } = useAuth()

  if (!user) {
    return null
  }

  return (
    <div className="home-page">
      <h1>JWT 인증 샘플</h1>
      <div className="user-info">
        <p>
          <strong>ID:</strong> {user.id}
        </p>
        <p>
          <strong>이메일:</strong> {user.email}
        </p>
        <p>
          <strong>닉네임:</strong> {user.nickname}
        </p>
        <p>
          <strong>역할:</strong> {user.role}
        </p>
      </div>
      <button
        type="button"
        onClick={() => {
          logout()
        }}
      >
        로그아웃
      </button>
    </div>
  )
}
