package com.jwtsample.springboot.security.cookie;

import com.jwtsample.springboot.config.properties.AdminCookieProperties;
import com.jwtsample.springboot.config.properties.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

// 관리자 Refresh Token Cookie 생성·삭제·읽기 담당.
// RefreshTokenCookieManager와 구조는 동일하고 AdminCookieProperties를 주입받는다는 점만 다르다.
@Component
@RequiredArgsConstructor
public class AdminRefreshTokenCookieManager {

	private final AdminCookieProperties adminCookieProperties;
	private final JwtProperties jwtProperties;

	public ResponseCookie createRefreshTokenCookie(String refreshTokenValue) {
		return ResponseCookie.from(adminCookieProperties.getName(), refreshTokenValue)
			.httpOnly(true)
			.secure(adminCookieProperties.isSecure())
			// sameSite: 외부 사이트에서 시작된 요청에 브라우저가 이 Cookie를 첨부할지 결정한다.
			//   Strict — cross-site 요청에 Cookie 미전송. 외부 링크 클릭 시 로그인이 풀리지만 보안이 가장 강하다.
			//   Lax    — 링크 클릭(GET)에는 Cookie 전송, cross-site POST form은 차단.
			// 관리자 페이지는 외부 링크 유입보다 보안이 중요하므로 Strict가 적합하다.
			// Lax로 변경하더라도 CookieCsrfDefenseFilter(Origin 검증 + X-Requested-With)가 cross-site POST를 추가로 막는다.
			.sameSite(adminCookieProperties.getSameSite())
			// path: 브라우저가 Cookie를 어느 요청에 첨부할지 결정하는 기준 경로.
			// 요청 URL이 이 경로로 시작할 때만 Cookie를 자동으로 첨부하고, 그 외 요청에는 보내지 않는다.
			//
			// 브라우저는 Cookie를 (name + domain + path) 조합으로 식별한다.
			// 따라서 이름이 같아도 path가 다르면 브라우저는 이를 별개의 Cookie로 저장·관리한다.
			// → path 분리만으로도 사용자/관리자 Cookie가 서로 다른 엔드포인트에 섞이는 문제를 방지할 수 있다.
			// → name까지 다르게 하는 것은 path가 실수로 넓어질 경우를 대비한 추가 안전망(Defense in Depth)이다.
			.path(adminCookieProperties.getPath())
			.maxAge(jwtProperties.getRefreshExpiration() / 1000)
			.build();
	}

	public ResponseCookie createClearCookie() {
		return ResponseCookie.from(adminCookieProperties.getName(), "")
			.httpOnly(true)
			.secure(adminCookieProperties.isSecure())
			.sameSite(adminCookieProperties.getSameSite())
			.path(adminCookieProperties.getPath())
			.maxAge(0)
			.build();
	}

	public Optional<String> getRefreshTokenFromCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return Optional.empty();
		}

		return Arrays.stream(cookies)
			.filter(cookie -> adminCookieProperties.getName().equals(cookie.getName()))
			.map(Cookie::getValue)
			.filter(value -> value != null && !value.isBlank())
			.findFirst();
	}
}
