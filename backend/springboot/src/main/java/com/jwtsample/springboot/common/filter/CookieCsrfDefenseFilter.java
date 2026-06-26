package com.jwtsample.springboot.common.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwtsample.springboot.common.exception.ErrorCode;
import com.jwtsample.springboot.common.exception.ErrorResponse;
import com.jwtsample.springboot.config.properties.CorsProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

// Cookie 기반 엔드포인트(refresh, logout)를 CSRF 공격으로부터 보호하는 필터.
//
// CSRF란: 공격자가 희생자의 브라우저를 이용해 희생자 모르게 요청을 보내는 공격.
//   예) 악성 사이트에서 <form action="https://example.com/api/auth/logout" method="POST">를 몰래 실행.
//   브라우저가 Cookie를 자동으로 첨부하므로 서버가 정상 요청으로 오인할 수 있다.
//
// 3중 방어 구조:
//   1. SameSite=Strict Cookie  : 외부 사이트 요청 시 브라우저가 Cookie 자체를 보내지 않는다.
//   2. Origin/Referer 헤더 검증 : 허용된 도메인 목록과 대조해 외부 요청을 차단한다.
//   3. X-Requested-With 커스텀 헤더 요구: 단순 <form>은 커스텀 헤더를 보낼 수 없다.
@Component
@RequiredArgsConstructor
public class CookieCsrfDefenseFilter extends OncePerRequestFilter {

	private static final String REFRESH_PATH = "/api/auth/refresh";
	private static final String LOGOUT_PATH = "/api/auth/logout";
	private static final String ADMIN_REFRESH_PATH = "/api/admin/auth/refresh";
	private static final String ADMIN_LOGOUT_PATH = "/api/admin/auth/logout";
	private static final String CUSTOM_HEADER_NAME = "X-Requested-With";
	private static final String CUSTOM_HEADER_VALUE = "XMLHttpRequest";

	private final CorsProperties corsProperties;
	private final ObjectMapper objectMapper;

	@Override
	protected void doFilterInternal(
		HttpServletRequest request,
		HttpServletResponse response,
		FilterChain filterChain
	) throws ServletException, IOException {
		String requestUri = request.getRequestURI();
		String method = request.getMethod();

		// Cookie를 사용하는 POST 엔드포인트만 검증한다. GET 등 다른 메서드는 통과.
		if ("POST".equals(method) && isCookieAuthEndpoint(requestUri)) {
			if (!isValidOrigin(request) || !isValidCustomHeader(request)) {
				writeForbiddenResponse(response);
				return;
			}
		}

		filterChain.doFilter(request, response);
	}

	private boolean isCookieAuthEndpoint(String requestUri) {
		return REFRESH_PATH.equals(requestUri) || LOGOUT_PATH.equals(requestUri)
			|| ADMIN_REFRESH_PATH.equals(requestUri) || ADMIN_LOGOUT_PATH.equals(requestUri);
	}

	// Origin 또는 Referer가 허용 목록과 일치하는지 검증한다.
	private boolean isValidOrigin(HttpServletRequest request) {
		List<String> allowedOrigins = corsProperties.getAllowedOrigins();

		// Origin 헤더: cross-origin 요청 시 브라우저가 자동으로 추가하는 출처 정보. 가장 신뢰도가 높다.
		String origin = request.getHeader("Origin");
		if (origin != null && !origin.isBlank()) {
			return allowedOrigins.contains(origin);
		}

		// Referer 헤더: 요청을 보낸 페이지의 전체 URL. Origin이 없을 때 대안으로 사용.
		String referer = request.getHeader("Referer");
		if (referer != null && !referer.isBlank()) {
			return allowedOrigins.stream().anyMatch(referer::startsWith);
		}

		// Sec-Fetch-Site: 최신 브라우저가 자동으로 추가하는 요청 출처 분류 헤더.
		// same-origin만 허용한다. same-site(서브도메인 포함)는 허용하지 않는다.
		// → 서브도메인(예: evil.mysite.com)이 공격자에게 탈취된 경우 same-site를 허용하면 CSRF가 가능하다.
		// → 프론트엔드가 서브도메인(api.mysite.com ↔ mysite.com)이라면 Origin 검증 단계에서 allowedOrigins로 처리한다.
		String secFetchSite = request.getHeader("Sec-Fetch-Site");
		if ("same-origin".equals(secFetchSite)) {
			return true;
		}

		return false;
	}

	// 단순 HTML <form>은 커스텀 헤더를 보낼 수 없어 CSRF 공격에 사용되기 어렵다.
	// fetch/axios처럼 커스텀 헤더를 설정할 수 있는 클라이언트만 이 검사를 통과한다.
	private boolean isValidCustomHeader(HttpServletRequest request) {
		String headerValue = request.getHeader(CUSTOM_HEADER_NAME);
		return CUSTOM_HEADER_VALUE.equals(headerValue);
	}

	private void writeForbiddenResponse(HttpServletResponse response) throws IOException {
		response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");
		objectMapper.writeValue(response.getWriter(), ErrorResponse.of(ErrorCode.CSRF_VALIDATION_FAILED));
	}
}
