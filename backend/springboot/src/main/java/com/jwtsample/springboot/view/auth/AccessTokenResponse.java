package com.jwtsample.springboot.view.auth;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AccessTokenResponse {

	private final String accessToken;
	private final String tokenType;
	private final long expiresIn;
}
