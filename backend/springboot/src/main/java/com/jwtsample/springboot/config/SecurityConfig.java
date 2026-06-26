package com.jwtsample.springboot.config;

import com.jwtsample.springboot.common.filter.CookieCsrfDefenseFilter;
import com.jwtsample.springboot.config.properties.AdminCookieProperties;
import com.jwtsample.springboot.config.properties.CookieProperties;
import com.jwtsample.springboot.config.properties.CorsProperties;
import com.jwtsample.springboot.config.properties.JwtProperties;
import com.jwtsample.springboot.config.properties.RefreshTokenProperties;
import com.jwtsample.springboot.security.CustomUserDetailsService;
import com.jwtsample.springboot.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

// Spring Security 전체 설정.
// 어떤 URL을 인증 없이 허용할지, 세션·CSRF·CORS 정책, 커스텀 필터 등록 순서를 한 곳에서 관리한다.
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({
	JwtProperties.class,
	CookieProperties.class,
	AdminCookieProperties.class,
	CorsProperties.class,
	RefreshTokenProperties.class
})
@RequiredArgsConstructor
public class SecurityConfig {

	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final CookieCsrfDefenseFilter cookieCsrfDefenseFilter;
	private final CustomUserDetailsService customUserDetailsService;
	private final CorsProperties corsProperties;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			// Bearer JWT 기반 stateless API이므로 Spring CSRF 토큰은 비활성화.
			// Cookie 기반 refresh/logout은 CookieCsrfDefenseFilter(SameSite + Origin + 커스텀 헤더)로 보완.
			.csrf(AbstractHttpConfigurer::disable)
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			// STATELESS: 서버가 세션을 생성·유지하지 않는다. 인증 정보는 요청마다 JWT로 전달한다.
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.userDetailsService(customUserDetailsService)
			.authorizeHttpRequests(auth -> auth
				// signup, login은 인증 없이 접근 가능 (로그인 전이므로 당연히 토큰이 없다)
				.requestMatchers(HttpMethod.POST, "/api/auth/signup", "/api/auth/login").permitAll()
				// refresh, logout도 permitAll: 이미 만료되거나 로그아웃된 상태에서도 호출할 수 있어야 한다.
				// 인증 여부는 Cookie의 Refresh Token으로 확인하지, Bearer JWT가 아니다.
				.requestMatchers(HttpMethod.POST, "/api/auth/refresh", "/api/auth/logout").permitAll()
				// 관리자 로그인도 공개 엔드포인트 (로그인 전이므로 토큰 없음)
				.requestMatchers(HttpMethod.POST, "/api/admin/auth/login").permitAll()
				// 관리자 refresh/logout도 Cookie 기반이므로 permitAll (위 사용자와 동일한 이유)
				.requestMatchers(HttpMethod.POST, "/api/admin/auth/refresh", "/api/admin/auth/logout").permitAll()
				// /api/admin/** 나머지는 ADMIN 역할을 가진 JWT가 있어야 통과한다.
				// Spring Security의 hasRole("ADMIN")은 내부적으로 ROLE_ADMIN 권한을 확인한다(UserPrincipal 참고).
				.requestMatchers("/api/admin/**").hasRole("ADMIN")
				// 그 외 모든 요청은 유효한 JWT가 있어야 통과한다.
				.anyRequest().authenticated()
			)
			// 커스텀 필터를 Spring Security 기본 인증 필터보다 먼저 실행한다.
			.addFilterBefore(cookieCsrfDefenseFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		// CORS(Cross-Origin Resource Sharing): 다른 도메인(예: localhost:5173)에서 오는 요청을 허용한다.
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(corsProperties.getAllowedOrigins());
		configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(List.of("*"));
		// withCredentials: true 요청에는 allowedOrigins를 "*"가 아닌 명시적 도메인으로 지정해야 한다.
		// "*"로 설정하면 브라우저가 자격증명 포함 요청을 거부한다.
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		// BCrypt: Blowfish 암호를 기반으로 만들어진 비밀번호 전용 단방향 해시 알고리즘.
		//
		// 결과 문자열 구조 (총 60자):
		//   $2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
		//   ---- --  ----------------------  -------------------------------
		//   버전 cost       salt(22자)                  hash(31자)
		//
		//   $ : 구분자 (각 필드를 나누는 역할)
		//   2a: BCrypt 알고리즘 버전 (2a, 2b 등 사소한 차이)
		//   10: cost 파라미터. 내부 반복 횟수 = 2^10 = 1,024회.
		//       숫자가 클수록 느려지므로 무차별 대입(brute-force) 공격이 어려워진다.
		//       서버 성능에 따라 조정 가능 — new BCryptPasswordEncoder(12)
		//   salt(22자): encode() 호출 시 자동 생성되는 랜덤값. 이 값이 매번 달라서
		//       같은 비밀번호라도 호출마다 다른 해시가 나온다.
		//   hash(31자): 비밀번호 + salt + cost를 조합해 계산한 실제 해시값.
		//
		// matches(입력값, 저장된해시) 동작 원리:
		//   새 salt를 생성하지 않고, 저장된 해시 문자열에서 salt와 cost를 꺼낸다.
		//   → 입력값을 꺼낸 salt·cost로 다시 해시
		//   → 결과를 저장된 hash 부분과 비교
		//   같은 조건(salt·cost)으로 만들었으므로 동일 비밀번호면 결과가 일치한다.
		//
		// DB가 유출되더라도 hash는 단방향이라 원문 비밀번호를 역추적하기 어렵다.
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}
}
