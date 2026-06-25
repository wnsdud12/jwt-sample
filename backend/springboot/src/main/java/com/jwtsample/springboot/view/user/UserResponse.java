package com.jwtsample.springboot.view.user;

import com.jwtsample.springboot.model.user.Role;
import com.jwtsample.springboot.model.user.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserResponse {

	private final Long id;
	private final String email;
	private final String nickname;
	private final Role role;

	public static UserResponse from(User user) {
		return UserResponse.builder()
			.id(user.getId())
			.email(user.getEmail())
			.nickname(user.getNickname())
			.role(user.getRole())
			.build();
	}
}
