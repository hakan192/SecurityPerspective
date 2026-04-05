export type Role = 'admin' | 'security_analyst' | 'reviewer' | 'stakeholder'

export interface TokenResponse {
  access_token: string
  token_type: string
  role: Role
}
