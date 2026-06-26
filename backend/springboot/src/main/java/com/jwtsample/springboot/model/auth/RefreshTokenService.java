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

// Refresh Token의 생성·검증·Rotation·폐기를 담당하는 서비스.
// Redis에는 원문이 아닌 해시만 저장하고, Rotation + Reuse Detection으로 탈취 감지를 구현한다.
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
	// refreshTokenId: Redis에서 토큰을 찾는 키 역할
	// rawToken: 해시 검증에 사용하는 원문 (Cookie에만 존재, Redis에는 해시만 저장)
	public record RefreshTokenPair(String refreshTokenId, String rawToken, String cookieValue, Long userId) {
	}

	// Rotation 결과. grace 중복 요청이면 cookieValue가 없다 (Redis에 원문 저장하지 않음).
	public record RotateResult(Long userId, Optional<String> cookieValue) {

		public static RotateResult rotated(RefreshTokenPair pair) {
			return new RotateResult(pair.userId(), Optional.of(pair.cookieValue()));
		}

		public static RotateResult graceReplay(Long userId) {
			return new RotateResult(userId, Optional.empty());
		}
	}

	private static final String GRACE_MARKER = "1";

	// 로그인 시 새 Refresh Token을 생성하고 Redis에 저장한다.
	public RefreshTokenPair createRefreshToken(Long userId) {
		// UUID: 충돌 확률이 극히 낮은 고유 ID. 여러 기기/탭에서 로그인해도 각각 다른 토큰 ID로 관리된다.
		String refreshTokenId = UUID.randomUUID().toString();
		// SecureRandom: 예측 불가능한 난수 생성기. Math.random()처럼 예측 가능한 값을 쓰면 안 된다.
		String rawToken = generateRawToken();
		String tokenHash = tokenHasher.hash(rawToken);
		// Cookie 값: "UUID.rawToken" 형태로 조합한다.
		// ID로 Redis 키를 찾고, rawToken으로 해시 검증을 한다.
		String cookieValue = refreshTokenId + "." + rawToken;

		saveRefreshToken(refreshTokenId, userId, tokenHash);
		addRefreshTokenToUser(userId, refreshTokenId);

		return new RefreshTokenPair(refreshTokenId, rawToken, cookieValue, userId);
	}

	// Refresh Token을 검증한 뒤 새 토큰으로 교체(Rotation)한다.
	// Rotation: 토큰을 사용할 때마다 새 토큰으로 교체해 탈취된 토큰의 재사용을 감지한다.
	public RotateResult rotateRefreshToken(String cookieValue) {
		String[] parts = parseCookieValue(cookieValue);
		String refreshTokenId = parts[0];
		String rawToken = parts[1];

		String storeKey = REFRESH_TOKEN_STORE_PREFIX + refreshTokenId;
		String storedValue = redisTemplate.opsForValue().get(storeKey);

		if (storedValue == null) {
			// Redis에 해당 ID가 없으면 만료되었거나 이미 폐기된 토큰이다.
			throw new AuthException(ErrorCode.INVALID_TOKEN);
		}

		String[] storedParts = storedValue.split(":");
		Long userId = Long.parseLong(storedParts[0]);
		String storedHash = storedParts[1];
		String presentedHash = tokenHasher.hash(rawToken);

		if (!tokenHasher.matches(rawToken, storedHash)) {
			// 현재 Redis에 저장된 해시와 불일치 → 이미 Rotation된 이전 토큰일 수 있음
			String graceKey = REFRESH_TOKEN_GRACE_PREFIX + refreshTokenId + ":" + presentedHash;

			if (Boolean.TRUE.equals(redisTemplate.hasKey(graceKey))) {
				// grace period 내 중복 요청: access token만 재발급, Set-Cookie는 생략.
				// (첫 요청이 이미 Cookie를 갱신했거나, 프론트 single-flight가 응답을 공유함)
				return RotateResult.graceReplay(userId);
			}

			// Grace period 이후 이전 Refresh Token 재사용 → 토큰 탈취 가능성.
			// 해당 사용자의 모든 Refresh Token을 무효화해 피해를 최소화한다.
			revokeAllUserRefreshTokens(userId);
			throw new AuthException(ErrorCode.TOKEN_REUSE_DETECTED);
		}

		String newRawToken = generateRawToken();
		String newHash = tokenHasher.hash(newRawToken);
		String newCookieValue = refreshTokenId + "." + newRawToken;

		// Redis에 새 해시로 덮어쓴다. 이전 토큰은 더 이상 유효하지 않다.
		saveRefreshToken(refreshTokenId, userId, newHash);
		// Rotation 직전 토큰 해시를 grace 키로만 보관 (값에는 원문/해시 저장 안 함)
		saveGraceRefreshToken(refreshTokenId, presentedHash);

		return RotateResult.rotated(new RefreshTokenPair(refreshTokenId, newRawToken, newCookieValue, userId));
	}

	// 단일 Refresh Token을 폐기한다. 로그아웃 시 사용.
	public void revokeRefreshToken(String cookieValue) {
		String[] parts = parseCookieValue(cookieValue);
		String refreshTokenId = parts[0];

		String storeKey = REFRESH_TOKEN_STORE_PREFIX + refreshTokenId;
		String storedValue = redisTemplate.opsForValue().get(storeKey);

		if (storedValue != null) {
			Long userId = Long.parseLong(storedValue.split(":")[0]);
			redisTemplate.delete(storeKey);
			// 사용자 인덱스에서도 이 ID를 제거한다.
			redisTemplate.opsForSet().remove(REFRESH_TOKEN_USER_PREFIX + userId, refreshTokenId);
		}
	}

	// 해당 사용자의 모든 Refresh Token을 폐기한다. Reuse Detection 시 사용.
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
		// 원문이나 해시를 값에 넣지 않는다. 키 자체가 "이전 해시를 제시했다"는 증거 역할을 한다.
		String graceKey = REFRESH_TOKEN_GRACE_PREFIX + refreshTokenId + ":" + oldTokenHash;
		redisTemplate.opsForValue().set(graceKey, GRACE_MARKER, GRACE_TTL);
	}

	private void saveRefreshToken(String refreshTokenId, Long userId, String tokenHash) {
		String storeKey = REFRESH_TOKEN_STORE_PREFIX + refreshTokenId;
		// 값: "userId:tokenHash" 형태로 저장한다. 원문은 저장하지 않는다.
		String value = userId + ":" + tokenHash;
		Duration ttl = Duration.ofMillis(jwtProperties.getRefreshExpiration());
		redisTemplate.opsForValue().set(storeKey, value, ttl);
	}

	private void addRefreshTokenToUser(Long userId, String refreshTokenId) {
		// 사용자 인덱스: 한 사용자가 발급한 모든 Refresh Token ID 목록.
		// Reuse Detection 시 해당 사용자의 모든 토큰을 한 번에 폐기할 때 사용한다.
		String userIndexKey = REFRESH_TOKEN_USER_PREFIX + userId;
		redisTemplate.opsForSet().add(userIndexKey, refreshTokenId);
		redisTemplate.expire(userIndexKey, Duration.ofMillis(jwtProperties.getRefreshExpiration()));
	}

	private String generateRawToken() {
		byte[] bytes = new byte[32];
		secureRandom.nextBytes(bytes);
		// URL-safe Base64 (패딩 없음): '+'·'/'·'=' 없이 URL에 안전한 문자만 사용한다.
		// 결과: A-Za-z0-9_- 문자로 구성된 43자 문자열 (256비트 엔트로피)
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private String[] parseCookieValue(String cookieValue) {
		// Cookie 값 형식: "{UUID}.{rawToken}"
		// UUID에는 '.'이 없고, rawToken(Base64URL without padding)에도 '.'이 없으므로
		// 첫 번째 '.'이 유일한 구분자다.
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
