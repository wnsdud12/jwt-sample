package com.jwtsample.springboot.model.auth;

import com.jwtsample.springboot.common.exception.AuthException;
import com.jwtsample.springboot.common.exception.ErrorCode;
import com.jwtsample.springboot.model.user.User;
import com.jwtsample.springboot.model.user.UserService;
import com.jwtsample.springboot.security.UserPrincipal;
import com.jwtsample.springboot.security.cookie.RefreshTokenCookieManager;
import com.jwtsample.springboot.security.jwt.JwtTokenProvider;
import com.jwtsample.springboot.view.auth.AccessTokenResponse;
import com.jwtsample.springboot.view.auth.LoginRequest;
import com.jwtsample.springboot.view.auth.SignupRequest;
import com.jwtsample.springboot.view.user.UserResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

	private final UserService userService;
	private final RefreshTokenService refreshTokenService;
	private final RefreshTokenCookieManager refreshTokenCookieManager;
	private final JwtTokenProvider jwtTokenProvider;
	private final PasswordEncoder passwordEncoder;

	public record TokenWithCookie(AccessTokenResponse accessToken, ResponseCookie refreshCookie) {
	}

	@Transactional
	public UserResponse signup(SignupRequest request) {
		return userService.signup(request);
	}

	@Transactional
	public TokenWithCookie login(LoginRequest request) {
		User user = userService.findByEmail(request.getEmail());

		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
		}

		UserPrincipal userPrincipal = new UserPrincipal(user);
		RefreshTokenService.RefreshTokenPair tokenPair = refreshTokenService.createRefreshToken(user.getId());
		ResponseCookie refreshCookie = refreshTokenCookieManager.createRefreshTokenCookie(tokenPair.cookieValue());

		return new TokenWithCookie(buildAccessTokenResponse(userPrincipal), refreshCookie);
	}

	public TokenWithCookie refresh(HttpServletRequest request) {
		String cookieValue = refreshTokenCookieManager.getRefreshTokenFromCookie(request)
			.orElseThrow(() -> new AuthException(ErrorCode.INVALID_TOKEN));

		RefreshTokenService.RefreshTokenPair rotatedPair = refreshTokenService.rotateRefreshToken(cookieValue);
		ResponseCookie refreshCookie = refreshTokenCookieManager.createRefreshTokenCookie(rotatedPair.cookieValue());

		User user = userService.getUserEntityById(rotatedPair.userId());
		return new TokenWithCookie(buildAccessTokenResponse(new UserPrincipal(user)), refreshCookie);
	}

	public ResponseCookie logout(HttpServletRequest request) {
		refreshTokenCookieManager.getRefreshTokenFromCookie(request)
			.ifPresent(refreshTokenService::revokeRefreshToken);
		return refreshTokenCookieManager.createClearCookie();
	}

	private AccessTokenResponse buildAccessTokenResponse(UserPrincipal userPrincipal) {
		String accessToken = jwtTokenProvider.createAccessToken(userPrincipal);
		return AccessTokenResponse.builder()
			.accessToken(accessToken)
			.tokenType("Bearer")
			.expiresIn(jwtTokenProvider.getAccessExpiration() / 1000)
			.build();
	}
}
