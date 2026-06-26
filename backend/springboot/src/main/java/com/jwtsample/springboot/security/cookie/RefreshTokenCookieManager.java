package com.jwtsample.springboot.security.cookie;

import com.jwtsample.springboot.config.properties.CookieProperties;
import com.jwtsample.springboot.config.properties.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

// Refresh Token Cookie의 생성·삭제·읽기를 담당하는 유틸리티.
@Component
@RequiredArgsConstructor
public class RefreshTokenCookieManager {

	private final CookieProperties cookieProperties;
	private final JwtProperties jwtProperties;

	// Refresh Token을 HttpOnly + Secure + SameSite=Strict Cookie로 만든다.
	public ResponseCookie createRefreshTokenCookie(String refreshTokenValue) {
		return ResponseCookie.from(cookieProperties.getName(), refreshTokenValue)
			// httpOnly: JavaScript(document.cookie)에서 읽을 수 없다. XSS 공격으로부터 토큰 보호.
			.httpOnly(true)
			// secure: HTTPS 연결에서만 전송. application-local.yml의 app.cookie.secure 값으로 제어.
			.secure(cookieProperties.isSecure())
			// sameSite=Strict: 다른 사이트에서 시작된 요청에 브라우저가 이 Cookie를 보내지 않는다. CSRF 방어 1계층.
			.sameSite(cookieProperties.getSameSite())
			// path: 브라우저가 Cookie를 어느 요청에 첨부할지 결정하는 기준 경로.
			// 요청 URL이 이 경로로 시작할 때만 Cookie를 자동으로 첨부하고, 그 외 요청에는 보내지 않는다.
			//
			// 브라우저는 Cookie를 (name + domain + path) 조합으로 식별한다.
			// 따라서 이름이 같아도 path가 다르면 브라우저는 이를 별개의 Cookie로 저장·관리한다.
			//
			// 예) 사용자: path=/api/auth  /  관리자: path=/api/admin/auth
			//   POST /api/auth/refresh       → 사용자 Cookie만 전송 (path 일치)
			//   POST /api/admin/auth/refresh → 관리자 Cookie만 전송 (path 일치)
			//   GET  /api/users/me           → 어느 쪽도 전송 안 됨  (path 미해당)
			//
			// path 분리만으로도 쿠키 충돌을 막는 데 충분하다.
			// name까지 다르게 설정하는 것은 path가 실수로 넓어졌을 때를 대비한 추가 안전망(Defense in Depth)이다.
			.path(cookieProperties.getPath())
			// maxAge: 초 단위 만료 시간. 브라우저가 이 시간이 지나면 Cookie를 자동으로 삭제한다.
			.maxAge(jwtProperties.getRefreshExpiration() / 1000)
			.build();
	}

	// 로그아웃 시 Cookie를 즉시 만료시키는 빈 Cookie를 반환한다.
	public ResponseCookie createClearCookie() {
		return ResponseCookie.from(cookieProperties.getName(), "")
			.httpOnly(true)
			.secure(cookieProperties.isSecure())
			.sameSite(cookieProperties.getSameSite())
			.path(cookieProperties.getPath())
			// maxAge(0): 만료 시간을 0으로 설정해 브라우저가 즉시 Cookie를 삭제하게 한다.
			.maxAge(0)
			.build();
	}

	public Optional<String> getRefreshTokenFromCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return Optional.empty();
		}

		return Arrays.stream(cookies)
			.filter(cookie -> cookieProperties.getName().equals(cookie.getName()))
			.map(Cookie::getValue)
			.filter(value -> value != null && !value.isBlank())
			.findFirst();
	}
}
