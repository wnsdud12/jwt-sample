package com.jwtsample.springboot.model.auth;

import com.jwtsample.springboot.common.exception.AuthException;
import com.jwtsample.springboot.common.exception.ErrorCode;
import com.jwtsample.springboot.config.properties.JwtProperties;
import com.jwtsample.springboot.security.hash.TokenHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

	// Redis 키 네임스페이스 (refresh:refreshToken 같은 중복 접두사 사용 안 함)
	private static final String REFRESH_TOKEN_STORE_PREFIX = "refreshToken:";       // + {refreshTokenId}
	private static final String REFRESH_TOKEN_USER_PREFIX = "refreshToken:user:";   // + {userId}
	private static final String REFRESH_TOKEN_GRACE_PREFIX = "refreshToken:grace:"; // + {refreshTokenId}:{hash}
	// Rotation 직후 grace period: 이전 Refresh Token으로 들어온 중복 요청 허용
	// - React StrictMode 개발 모드 이중 호출
	// - 연속 F5로 Set-Cookie 반영 전 같은 토큰이 재전송되는 경우
	// grace period 이후 같은 이전 토큰이 오면 재사용 공격(TOKEN_REUSE_DETECTED)으로 처리
	private static final Duration GRACE_TTL = Duration.ofSeconds(30);

	private final StringRedisTemplate redisTemplate;
	private final TokenHasher tokenHasher;
	private final JwtProperties jwtProperties;
	private final SecureRandom secureRandom = new SecureRandom();

	// Cookie 값 형식: {refreshTokenId}.{rawToken}
	public record RefreshTokenPair(String refreshTokenId, String rawToken, String cookieValue, Long userId) {
	}

	// Rotation 결과 — grace 중복 요청이면 cookieValue 없음 (Redis에 원문 저장하지 않음)
	public record RotateResult(Long userId, Optional<String> cookieValue) {

		public static RotateResult rotated(RefreshTokenPair pair) {
			return new RotateResult(pair.userId(), Optional.of(pair.cookieValue()));
		}

		public static RotateResult graceReplay(Long userId) {
			return new RotateResult(userId, Optional.empty());
		}
	}

	private static final String GRACE_MARKER = "1";

	// 로그인 시 새 Refresh Token 생성
	public RefreshTokenPair createRefreshToken(Long userId) {
		String refreshTokenId = UUID.randomUUID().toString();
		String rawToken = generateRawToken();
		String tokenHash = tokenHasher.hash(rawToken);
		String cookieValue = refreshTokenId + "." + rawToken;

		saveRefreshToken(refreshTokenId, userId, tokenHash);
		addRefreshTokenToUser(userId, refreshTokenId);

		return new RefreshTokenPair(refreshTokenId, rawToken, cookieValue, userId);
	}

	// Refresh Token 검증 후 Rotation (새 rawToken 발급 + Redis 해시 교체)
	public RotateResult rotateRefreshToken(String cookieValue) {
		String[] parts = parseCookieValue(cookieValue);
		String refreshTokenId = parts[0];
		String rawToken = parts[1];

		String storeKey = REFRESH_TOKEN_STORE_PREFIX + refreshTokenId;
		String storedValue = redisTemplate.opsForValue().get(storeKey);

		if (storedValue == null) {
			throw new AuthException(ErrorCode.INVALID_TOKEN);
		}

		String[] storedParts = storedValue.split(":");
		Long userId = Long.parseLong(storedParts[0]);
		String storedHash = storedParts[1];
		String presentedHash = tokenHasher.hash(rawToken);

		if (!tokenHasher.matches(rawToken, storedHash)) {
			// 현재 해시와 불일치 → 이미 Rotation된 이전 Refresh Token일 수 있음
			String graceKey = REFRESH_TOKEN_GRACE_PREFIX + refreshTokenId + ":" + presentedHash;

			if (Boolean.TRUE.equals(redisTemplate.hasKey(graceKey))) {
				// grace period 내 중복 요청: access token만 재발급, Set-Cookie는 생략
				// (첫 요청이 이미 Cookie를 갱신했거나, 프론트 single-flight가 응답을 공유함)
				return RotateResult.graceReplay(userId);
			}

			// Grace period 이후 이전 Refresh Token 재사용 → 토큰 탈취 가능성, 사용자 전체 Refresh Token 무효화
			revokeAllUserRefreshTokens(userId);
			throw new AuthException(ErrorCode.TOKEN_REUSE_DETECTED);
		}

		String newRawToken = generateRawToken();
		String newHash = tokenHasher.hash(newRawToken);
		String newCookieValue = refreshTokenId + "." + newRawToken;

		saveRefreshToken(refreshTokenId, userId, newHash);
		// Rotation 직전 토큰 해시를 grace 키로만 보관 (값에는 원문/해시 저장 안 함)
		saveGraceRefreshToken(refreshTokenId, presentedHash);

		return RotateResult.rotated(new RefreshTokenPair(refreshTokenId, newRawToken, newCookieValue, userId));
	}

	public void revokeRefreshToken(String cookieValue) {
		String[] parts = parseCookieValue(cookieValue);
		String refreshTokenId = parts[0];

		String storeKey = REFRESH_TOKEN_STORE_PREFIX + refreshTokenId;
		String storedValue = redisTemplate.opsForValue().get(storeKey);

		if (storedValue != null) {
			Long userId = Long.parseLong(storedValue.split(":")[0]);
			redisTemplate.delete(storeKey);
			redisTemplate.opsForSet().remove(REFRESH_TOKEN_USER_PREFIX + userId, refreshTokenId);
		}
	}

	public void revokeAllUserRefreshTokens(Long userId) {
		String userIndexKey = REFRESH_TOKEN_USER_PREFIX + userId;
		Set<String> refreshTokenIds = redisTemplate.opsForSet().members(userIndexKey);

		if (refreshTokenIds != null) {
			for (String refreshTokenId : refreshTokenIds) {
				redisTemplate.delete(REFRESH_TOKEN_STORE_PREFIX + refreshTokenId);
			}
		}

		redisTemplate.delete(userIndexKey);
	}

	private void saveGraceRefreshToken(String refreshTokenId, String oldTokenHash) {
		// key: refreshToken:grace:{refreshTokenId}:{이전토큰해시} → 마커만 저장, TTL 30초
		String graceKey = REFRESH_TOKEN_GRACE_PREFIX + refreshTokenId + ":" + oldTokenHash;
		redisTemplate.opsForValue().set(graceKey, GRACE_MARKER, GRACE_TTL);
	}

	private void saveRefreshToken(String refreshTokenId, Long userId, String tokenHash) {
		String storeKey = REFRESH_TOKEN_STORE_PREFIX + refreshTokenId;
		String value = userId + ":" + tokenHash;
		Duration ttl = Duration.ofMillis(jwtProperties.getRefreshExpiration());
		redisTemplate.opsForValue().set(storeKey, value, ttl);
	}

	private void addRefreshTokenToUser(Long userId, String refreshTokenId) {
		String userIndexKey = REFRESH_TOKEN_USER_PREFIX + userId;
		redisTemplate.opsForSet().add(userIndexKey, refreshTokenId);
		redisTemplate.expire(userIndexKey, Duration.ofMillis(jwtProperties.getRefreshExpiration()));
	}

	private String generateRawToken() {
		byte[] bytes = new byte[32];
		secureRandom.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private String[] parseCookieValue(String cookieValue) {
		int dotIndex = cookieValue.indexOf('.');
		if (dotIndex <= 0 || dotIndex >= cookieValue.length() - 1) {
			throw new AuthException(ErrorCode.INVALID_TOKEN);
		}

		return new String[]{
			cookieValue.substring(0, dotIndex),
			cookieValue.substring(dotIndex + 1)
		};
	}
}
