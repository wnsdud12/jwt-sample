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
import org.springframework.lang.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// 로그인·회원가입·토큰 갱신·로그아웃 비즈니스 로직을 담당하는 서비스.
@Service
@RequiredArgsConstructor
// 클래스 기본값을 readOnly = true로 설정해 DB 읽기 최적화를 적용한다.
// 데이터를 수정하는 메서드에는 @Transactional을 별도로 붙여 쓰기 가능 트랜잭션으로 오버라이드한다.
@Transactional(readOnly = true)
public class AuthService {

	private final UserService userService;
	private final RefreshTokenService refreshTokenService;
	private final RefreshTokenCookieManager refreshTokenCookieManager;
	private final JwtTokenProvider jwtTokenProvider;
	private final PasswordEncoder passwordEncoder;

	// 서비스가 컨트롤러에 반환하는 묶음 타입.
	// Access Token + Refresh Cookie를 함께 반환해야 하는데 Java 메서드는 값을 하나만 반환할 수 있어 record로 묶는다.
	// refreshCookie가 null이면 grace 중복 요청으로 Cookie 갱신 없이 Access Token만 재발급한 경우다.
	public record TokenWithCookie(AccessTokenResponse accessToken, @Nullable ResponseCookie refreshCookie) {
	}

	@Transactional
	public UserResponse signup(SignupRequest request) {
		return userService.signup(request);
	}

	@Transactional
	public TokenWithCookie login(LoginRequest request) {
		// 1. 이메일로 사용자 조회
		User user = userService.findByEmail(request.getEmail());

		// 2. 비밀번호 검증 (BCrypt는 단방향이므로 matches()로 비교한다. 원문 복원은 불가능)
		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
		}

		// 3. Refresh Token 생성 → Redis 저장 + Cookie 생성
		UserPrincipal userPrincipal = new UserPrincipal(user);
		RefreshTokenService.RefreshTokenPair tokenPair = refreshTokenService.createRefreshToken(user.getId());
		ResponseCookie refreshCookie = refreshTokenCookieManager.createRefreshTokenCookie(tokenPair.cookieValue());

		// 4. Access Token(JWT) 생성
		return new TokenWithCookie(buildAccessTokenResponse(userPrincipal), refreshCookie);
	}

	public TokenWithCookie refresh(HttpServletRequest request) {
		// Cookie에서 Refresh Token을 꺼내 검증·Rotation을 수행한다.
		// Rotation 이후에야 새 Access Token을 발급하므로, 유효하지 않은 토큰으로는 재발급이 불가능하다.
		String cookieValue = refreshTokenCookieManager.getRefreshTokenFromCookie(request)
			.orElseThrow(() -> new AuthException(ErrorCode.INVALID_TOKEN));

		RefreshTokenService.RotateResult rotateResult = refreshTokenService.rotateRefreshToken(cookieValue);
		ResponseCookie refreshCookie = rotateResult.cookieValue()
			.map(refreshTokenCookieManager::createRefreshTokenCookie)
			.orElse(null);

		User user = userService.getUserEntityById(rotateResult.userId());
		return new TokenWithCookie(buildAccessTokenResponse(new UserPrincipal(user)), refreshCookie);
	}

	public ResponseCookie logout(HttpServletRequest request) {
		// 로그아웃 실패(Cookie 없음 등)는 무시하고 항상 만료 Cookie를 반환한다.
		// 이미 로그아웃된 사용자도 안전하게 재호출할 수 있어야 하기 때문이다.
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
