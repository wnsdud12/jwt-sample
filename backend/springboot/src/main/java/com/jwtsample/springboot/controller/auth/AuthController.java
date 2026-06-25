package com.jwtsample.springboot.controller.auth;

import com.jwtsample.springboot.model.auth.AuthService;
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

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthService authService;

	@PostMapping("/signup")
	public ResponseEntity<UserResponse> signup(@Valid @RequestBody SignupRequest request) {
		UserResponse response = authService.signup(request);
		return ResponseEntity.status(HttpStatus.CREATED).body(response);
	}

	@PostMapping("/login")
	public ResponseEntity<AccessTokenResponse> login(@Valid @RequestBody LoginRequest request) {
		AuthService.TokenWithCookie result = authService.login(request);
		return ResponseEntity.ok()
			.header(HttpHeaders.SET_COOKIE, result.refreshCookie().toString())
			.body(result.accessToken());
	}

	@PostMapping("/refresh")
	public ResponseEntity<AccessTokenResponse> refresh(HttpServletRequest request) {
		AuthService.TokenWithCookie result = authService.refresh(request);
		return ResponseEntity.ok()
			.header(HttpHeaders.SET_COOKIE, result.refreshCookie().toString())
			.body(result.accessToken());
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(HttpServletRequest request) {
		return ResponseEntity.noContent()
			.header(HttpHeaders.SET_COOKIE, authService.logout(request).toString())
			.build();
	}
}
