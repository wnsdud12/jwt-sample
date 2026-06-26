import { useAdminAuth } from '../../hooks/useAdminAuth'
import { useUsers } from '../../api/adminAuthApi'
import './AdminUsersPage.css'

export function AdminUsersPage() {
  const { adminLogout } = useAdminAuth()
  const { data: users, isLoading, isError } = useUsers()

  return (
    <div className="admin-page">
      <header className="admin-header">
        <h1>회원 목록</h1>
        <button className="admin-logout-btn" onClick={adminLogout}>
          로그아웃
        </button>
      </header>

      <main className="admin-content">
        {isLoading && <p className="admin-status">불러오는 중...</p>}
        {isError && <p className="admin-status admin-status--error">회원 목록을 불러오지 못했습니다.</p>}

        {users && (
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>이메일</th>
                  <th>닉네임</th>
                  <th>역할</th>
                </tr>
              </thead>
              <tbody>
                {users.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="admin-table-empty">
                      등록된 회원이 없습니다.
                    </td>
                  </tr>
                ) : (
                  users.map((user) => (
                    <tr key={user.id}>
                      <td>{user.id}</td>
                      <td>{user.email}</td>
                      <td>{user.nickname}</td>
                      <td>{user.role}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </main>
    </div>
  )
}
