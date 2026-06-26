package com.jwtsample.springboot.controller.admin;

import com.jwtsample.springboot.model.user.UserService;
import com.jwtsample.springboot.view.user.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

// 관리자 전용 사용자 관리 엔드포인트.
// /api/admin/** 는 SecurityConfig에서 ROLE_ADMIN 인증을 요구하므로 별도 권한 검사 없이 서비스를 호출한다.
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminUserController {

	private final UserService userService;

	@GetMapping("/users")
	public ResponseEntity<List<UserResponse>> getAllUsers() {
		return ResponseEntity.ok(userService.getAllUsers());
	}
}
