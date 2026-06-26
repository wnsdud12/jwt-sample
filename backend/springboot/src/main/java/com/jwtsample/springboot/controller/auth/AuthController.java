package com.jwtsample.springboot.controller.auth;

import com.jwtsample.springboot.model.auth.AuthService;
import com.jwtsample.springboot.model.auth.LoginRateLimitService;
import com.jwtsample.springboot.model.auth.TokenWithCookie;
import com.jwtsample.springboot.view.auth.AccessTokenResponse;
import com.jwtsample.springboot.view.auth.LoginRequest;
import com.jwtsample.springboot.view.auth.SignupRequest;
import com.jwtsample.springboot.view.user.UserResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// 인증 관련 HTTP 엔드포인트를 정의하는 컨트롤러.
// 비즈니스 로직은 AuthService로 위임하고, HTTP 응답 형식(상태코드, 헤더, 바디)에만 집중한다.
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthService authService;
	private final LoginRateLimitService loginRateLimitService;

	@PostMapping("/signup")
	public ResponseEntity<UserResponse> signup(@Valid @RequestBody SignupRequest request) {
		UserResponse response = authService.signup(request);
		// 201 Created: 새 리소스가 생성됐을 때의 표준 HTTP 상태코드.
		return ResponseEntity.status(HttpStatus.CREATED).body(response);
	}

	@PostMapping("/login")
	public ResponseEntity<AccessTokenResponse> login(
		@Valid @RequestBody LoginRequest request,
		HttpServletRequest httpRequest
	) {
		// Rate Limiting: IP별 1분에 최대 5회 요청만 허용한다.
		loginRateLimitService.checkAndIncrement(extractClientIp(httpRequest));
		TokenWithCookie result = authService.login(request);
		// Access Token은 JSON 바디로, Refresh Token은 Set-Cookie 헤더로 분리해 전달한다.
		// Set-Cookie는 HTTP 헤더에 담아야 하므로 ResponseEntity.header()로 직접 추가한다.
		return ResponseEntity.ok()
			.header(HttpHeaders.SET_COOKIE, result.refreshCookie().toString())
			.body(result.accessToken());
	}

	@PostMapping("/refresh")
	public ResponseEntity<AccessTokenResponse> refresh(HttpServletRequest request) {
		TokenWithCookie result = authService.refresh(request);
		ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.ok();
		// grace 중복 요청이면 refreshCookie가 null이다(RefreshTokenService.rotateRefreshToken 참고).
		// 이 경우 Set-Cookie 헤더를 생략하고 새 Access Token만 반환한다.
		if (result.refreshCookie() != null) {
			responseBuilder.header(HttpHeaders.SET_COOKIE, result.refreshCookie().toString());
		}
		return responseBuilder.body(result.accessToken());
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(HttpServletRequest request) {
		// 204 No Content: 처리는 성공했지만 반환할 바디가 없을 때의 표준 HTTP 상태코드.
		// Set-Cookie로 maxAge=0 Cookie를 내려보내 브라우저의 Refresh Token Cookie를 삭제한다.
		return ResponseEntity.noContent()
			.header(HttpHeaders.SET_COOKIE, authService.logout(request).toString())
			.build();
	}

	// 요청자의 실제 IP를 추출한다.
	// 리버스 프록시(nginx 등) 환경에서는 X-Forwarded-For 헤더에 원본 IP가 담긴다.
	// 여러 IP가 쉼표로 이어진 경우 첫 번째 값이 클라이언트 IP다.
	private String extractClientIp(HttpServletRequest request) {
		String forwarded = request.getHeader("X-Forwarded-For");
		if (forwarded != null && !forwarded.isBlank()) {
			return forwarded.split(",")[0].trim();
		}
		return request.getRemoteAddr();
	}
}
