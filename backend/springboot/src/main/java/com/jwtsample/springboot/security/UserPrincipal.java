package com.jwtsample.springboot.security;

import com.jwtsample.springboot.model.user.Role;
import com.jwtsample.springboot.model.user.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

// Spring Security가 인증 정보를 다루는 표준 인터페이스 UserDetails의 구현체.
// DB의 User 엔티티 대신 이 클래스가 Security 레이어와 소통한다.
// JWT 복원 시(두 번째 생성자)에는 DB 조회 없이 토큰의 클레임만으로 인스턴스를 만든다.
@Getter
public class UserPrincipal implements UserDetails {

	private final Long id;
	private final String email;
	private final String password;
	private final Role role;

	// DB에서 User를 조회한 뒤 UserPrincipal로 변환할 때 사용 (로그인 시)
	public UserPrincipal(User user) {
		this.id = user.getId();
		this.email = user.getEmail();
		this.password = user.getPassword();
		this.role = user.getRole();
	}

	// JWT에서 복원할 때 사용 (매 API 요청 시). DB 조회 없이 토큰 클레임만으로 생성하므로 비밀번호가 불필요하다.
	public UserPrincipal(Long id, String email, String roleName) {
		this.id = id;
		this.email = email;
		this.password = "";
		this.role = Role.valueOf(roleName);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// Spring Security는 권한 문자열에 "ROLE_" 접두사를 기대한다.
		// 예: "ROLE_USER", "ROLE_ADMIN"
		return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
	}

	@Override
	public String getUsername() {
		// UserDetails 인터페이스는 username을 기준으로 사용자를 식별한다.
		// 이 샘플에서는 email을 username으로 사용한다.
		return email;
	}

	// 이하 메서드들은 계정 상태(잠금·만료·비활성화)를 나타낸다.
	// 이 샘플에서는 관련 기능이 없으므로 모두 true를 반환한다.
	// 실무에서는 로그인 실패 횟수 초과 → isAccountNonLocked() = false 처리 등을 구현한다.
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}
