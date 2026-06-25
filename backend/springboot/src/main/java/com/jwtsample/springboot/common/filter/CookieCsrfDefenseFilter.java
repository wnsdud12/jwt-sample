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

@Component
@RequiredArgsConstructor
public class CookieCsrfDefenseFilter extends OncePerRequestFilter {

	private static final String REFRESH_PATH = "/api/auth/refresh";
	private static final String LOGOUT_PATH = "/api/auth/logout";
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

		if ("POST".equals(method) && isCookieAuthEndpoint(requestUri)) {
			if (!isValidOrigin(request) || !isValidCustomHeader(request)) {
				writeForbiddenResponse(response);
				return;
			}
		}

		filterChain.doFilter(request, response);
	}

	private boolean isCookieAuthEndpoint(String requestUri) {
		return REFRESH_PATH.equals(requestUri) || LOGOUT_PATH.equals(requestUri);
	}

	// Origin 또는 Referer가 허용 목록과 일치하는지 검증
	private boolean isValidOrigin(HttpServletRequest request) {
		List<String> allowedOrigins = corsProperties.getAllowedOrigins();
		String origin = request.getHeader("Origin");

		if (origin != null && !origin.isBlank()) {
			return allowedOrigins.contains(origin);
		}

		String referer = request.getHeader("Referer");
		if (referer != null && !referer.isBlank()) {
			return allowedOrigins.stream().anyMatch(referer::startsWith);
		}

		// Vite 프록시 등 same-origin 요청은 Origin/Referer가 없을 수 있음
		String secFetchSite = request.getHeader("Sec-Fetch-Site");
		if ("same-origin".equals(secFetchSite) || "same-site".equals(secFetchSite)) {
			return true;
		}

		return false;
	}

	// 단순 form CSRF를 막기 위해 커스텀 헤더 필수
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
