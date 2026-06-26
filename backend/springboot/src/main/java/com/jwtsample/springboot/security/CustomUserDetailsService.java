package com.jwtsample.springboot.security;

import com.jwtsample.springboot.model.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// Spring Security가 사용자를 조회할 때 호출하는 인터페이스 UserDetailsService의 구현체.
// 이 샘플은 JWT 기반이라 폼 로그인을 쓰지 않지만, SecurityConfig에서 AuthenticationManager Bean을
// 등록하기 위해 UserDetailsService 구현체가 필요하다.
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	// email(username)로 사용자를 조회해 UserDetails(UserPrincipal)로 반환한다.
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		return userRepository.findByEmail(email)
			.map(UserPrincipal::new)
			.orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
	}
}
