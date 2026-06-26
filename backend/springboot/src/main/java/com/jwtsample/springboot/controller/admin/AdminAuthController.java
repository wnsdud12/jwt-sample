package com.jwtsample.springboot.controller.admin;

import com.jwtsample.springboot.model.admin.AdminAuthService;
import com.jwtsample.springboot.view.auth.AccessTokenResponse;
import com.jwtsample.springboot.view.auth.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// 관리자 인증 엔드포인트. 구조는 AuthController와 동일하고 AdminAuthService를 사용한다.
@RestController
@RequestMapping("/api/admin/auth")
@RequiredArgsConstructor
public class AdminAuthController {

	private final AdminAuthService adminAuthService;

	@PostMapping("/login")
	public ResponseEntity<AccessTokenResponse> login(@Valid @RequestBody LoginRequest request) {
		AdminAuthService.TokenWithCookie result = adminAuthService.login(request);
		return ResponseEntity.ok()
			.header(HttpHeaders.SET_COOKIE, result.refreshCookie().toString())
			.body(result.accessToken());
	}

	@PostMapping("/refresh")
	public ResponseEntity<AccessTokenResponse> refresh(HttpServletRequest request) {
		AdminAuthService.TokenWithCookie result = adminAuthService.refresh(request);
		ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.ok();
		if (result.refreshCookie() != null) {
			responseBuilder.header(HttpHeaders.SET_COOKIE, result.refreshCookie().toString());
		}
		return responseBuilder.body(result.accessToken());
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(HttpServletRequest request) {
		return ResponseEntity.noContent()
			.header(HttpHeaders.SET_COOKIE, adminAuthService.logout(request).toString())
			.build();
	}
}
