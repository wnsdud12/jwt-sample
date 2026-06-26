package com.jwtsample.springboot.model.admin;

import com.jwtsample.springboot.common.exception.AuthException;
import com.jwtsample.springboot.common.exception.ErrorCode;
import com.jwtsample.springboot.model.auth.RefreshTokenService;
import com.jwtsample.springboot.model.user.Role;
import com.jwtsample.springboot.model.user.User;
import com.jwtsample.springboot.model.user.UserService;
import com.jwtsample.springboot.security.UserPrincipal;
import com.jwtsample.springboot.security.cookie.AdminRefreshTokenCookieManager;
import com.jwtsample.springboot.security.jwt.JwtTokenProvider;
import com.jwtsample.springboot.model.auth.TokenWithCookie;
import com.jwtsample.springboot.view.auth.AccessTokenResponse;
import com.jwtsample.springboot.view.auth.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 관리자 로그인·토큰 갱신·로그아웃 비즈니스 로직.
// 사용자 AuthService와 거의 동일하나 login()에서 Role.ADMIN 여부를 추가로 검증한다.
// Refresh Token 저장소(Redis)는 사용자와 공유한다. 사용자·관리자 토큰은 userId와 role JWT 클레임으로 구분한다.
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AdminAuthService {

	private final UserService userService;
	private final RefreshTokenService refreshTokenService;
	private final AdminRefreshTokenCookieManager adminCookieManager;
	private final JwtTokenProvider jwtTokenProvider;
	private final PasswordEncoder passwordEncoder;

	@Transactional
	public TokenWithCookie login(LoginRequest request) {
		User user = userService.findByEmail(request.getEmail());

		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
		}

		// 관리자 전용 엔드포인트이므로 ADMIN 역할이 아니면 접근을 거부한다.
		if (user.getRole() != Role.ADMIN) {
			throw new AuthException(ErrorCode.NOT_ADMIN);
		}

		UserPrincipal userPrincipal = new UserPrincipal(user);
		RefreshTokenService.RefreshTokenPair tokenPair = refreshTokenService.createRefreshToken(user.getId());
		ResponseCookie refreshCookie = adminCookieManager.createRefreshTokenCookie(tokenPair.cookieValue());

		return new TokenWithCookie(buildAccessTokenResponse(userPrincipal), refreshCookie);
	}

	public TokenWithCookie refresh(HttpServletRequest request) {
		String cookieValue = adminCookieManager.getRefreshTokenFromCookie(request)
			.orElseThrow(() -> new AuthException(ErrorCode.INVALID_TOKEN));

		RefreshTokenService.RotateResult rotateResult = refreshTokenService.rotateRefreshToken(cookieValue);
		ResponseCookie refreshCookie = rotateResult.cookieValue()
			.map(adminCookieManager::createRefreshTokenCookie)
			.orElse(null);

		User user = userService.getUserEntityById(rotateResult.userId());

		// 권한 재검증: 로그인 이후 관리자 권한이 박탈된 경우를 방어한다.
		// Refresh Token은 유효하더라도 현재 DB의 role이 ADMIN이 아니면 Refresh Token을 폐기하고 거부한다.
		if (user.getRole() != Role.ADMIN) {
			refreshTokenService.revokeRefreshToken(cookieValue);
			throw new AuthException(ErrorCode.NOT_ADMIN);
		}

		return new TokenWithCookie(buildAccessTokenResponse(new UserPrincipal(user)), refreshCookie);
	}

	public ResponseCookie logout(HttpServletRequest request) {
		adminCookieManager.getRefreshTokenFromCookie(request)
			.ifPresent(refreshTokenService::revokeRefreshToken);
		return adminCookieManager.createClearCookie();
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
