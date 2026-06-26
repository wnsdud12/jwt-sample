package com.jwtsample.springboot.security.jwt;

import com.jwtsample.springboot.security.UserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 모든 HTTP 요청에서 Authorization 헤더를 읽어 JWT를 검증하는 필터.
// OncePerRequestFilter: 포워드·리다이렉트 등으로 요청이 내부에서 재처리되더라도 이 필터는 한 번만 실행된다.
//
// 인증 성공 시 SecurityContextHolder에 인증 정보를 저장한다.
// 이후 컨트롤러는 @AuthenticationPrincipal 등으로 현재 사용자를 꺼낼 수 있다.
// 토큰이 없거나 유효하지 않으면 저장하지 않고 다음 필터로 넘긴다.
// 인증이 필요한 엔드포인트는 SecurityConfig의 .authenticated() 설정이 자동으로 거부한다.
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final String AUTHORIZATION_HEADER = "Authorization";
	private static final String BEARER_PREFIX = "Bearer ";

	private final JwtTokenProvider jwtTokenProvider;

	@Override
	protected void doFilterInternal(
		HttpServletRequest request,
		HttpServletResponse response,
		FilterChain filterChain
	) throws ServletException, IOException {
		String token = resolveToken(request);

		if (token != null && jwtTokenProvider.validateToken(token)) {
			// DB 조회 없이 토큰의 클레임만으로 사용자 정보를 복원한다.
			Long userId = jwtTokenProvider.getUserId(token);
			String email = jwtTokenProvider.getEmail(token);
			String roleName = jwtTokenProvider.getRole(token);

			UserPrincipal userPrincipal = new UserPrincipal(userId, email, roleName);
			UsernamePasswordAuthenticationToken authentication =
				new UsernamePasswordAuthenticationToken(userPrincipal, null, userPrincipal.getAuthorities());
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			// Spring Security가 이 스레드(요청)를 "인증된 사용자"로 인식하게 한다.
			// 이 줄 이후부터 컨트롤러에서 @AuthenticationPrincipal로 사용자 정보를 꺼낼 수 있다.
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		// 인증 여부와 관계없이 항상 다음 필터로 요청을 넘긴다.
		// 인증이 필요한 엔드포인트에 대한 차단은 필터 체인 이후 Spring Security가 처리한다.
		filterChain.doFilter(request, response);
	}

	// "Bearer eyJhb..." 형태의 헤더에서 "Bearer " 접두사를 제거하고 토큰 문자열만 반환한다.
	private String resolveToken(HttpServletRequest request) {
		String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
			return bearerToken.substring(BEARER_PREFIX.length());
		}
		return null;
	}
}
