package com.jwtsample.springboot.config;

import com.jwtsample.springboot.common.filter.CookieCsrfDefenseFilter;
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
		// BCrypt: 비밀번호 단방향 해시 알고리즘. salt가 내장되어 같은 입력이라도 매번 다른 해시값이 나온다.
		// DB가 유출되더라도 원문 비밀번호를 역추적하기 어렵다.
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}
}
