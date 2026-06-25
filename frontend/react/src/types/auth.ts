export interface User {
  id: number
  email: string
  nickname: string
  role: 'USER' | 'ADMIN'
}

export interface AccessTokenResponse {
  accessToken: string
  tokenType: string
  expiresIn: number
}

export interface LoginRequest {
  email: string
  password: string
}

export interface SignupRequest {
  email: string
  password: string
  nickname: string
}

export interface ErrorResponse {
  code: string
  message: string
  timestamp: string
}
