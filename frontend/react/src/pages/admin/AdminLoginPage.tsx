import { useState } from 'react'
import axios from 'axios'
import { useAdminAuth } from '../../hooks/useAdminAuth'
import type { ErrorResponse } from '../../types/auth'
import '../AuthPages.css'

export function AdminLoginPage() {
  const { adminLogin } = useAdminAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setErrorMessage('')
    setIsSubmitting(true)

    try {
      await adminLogin({ email, password })
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.data) {
        const errorData = error.response.data as ErrorResponse
        setErrorMessage(errorData.message)
      } else {
        setErrorMessage('로그인에 실패했습니다.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>관리자 로그인</h1>
        {errorMessage && <div className="auth-error">{errorMessage}</div>}
        <form className="auth-form" onSubmit={handleSubmit}>
          <label>
            이메일
            <input
              type="email"
              value={email}
              onChange={(event) => {
                setEmail(event.target.value)
              }}
              required
            />
          </label>
          <label>
            비밀번호
            <input
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value)
              }}
              required
            />
          </label>
          <button type="submit" disabled={isSubmitting}>
            {isSubmitting ? '로그인 중...' : '로그인'}
          </button>
        </form>
      </div>
    </div>
  )
}
