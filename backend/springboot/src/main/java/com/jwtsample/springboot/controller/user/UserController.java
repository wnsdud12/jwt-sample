package com.jwtsample.springboot.controller.user;

import com.jwtsample.springboot.model.user.UserService;
import com.jwtsample.springboot.security.UserPrincipal;
import com.jwtsample.springboot.view.user.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;

	@GetMapping("/me")
	public ResponseEntity<UserResponse> getMe(@AuthenticationPrincipal UserPrincipal userPrincipal) {
		UserResponse response = userService.getUserById(userPrincipal.getId());
		return ResponseEntity.ok(response);
	}
}
