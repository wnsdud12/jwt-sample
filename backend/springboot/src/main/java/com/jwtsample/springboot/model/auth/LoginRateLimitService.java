package com.jwtsample.springboot.model.auth;

import com.jwtsample.springboot.common.exception.AuthException;
import com.jwtsample.springboot.common.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

// IP 주소 기반 로그인 Rate Limiting 서비스.
// 무차별 대입 공격(brute-force)에서 계정을 보호하기 위해 단기간 과도한 로그인 요청을 차단한다.
@Service
@RequiredArgsConstructor
public class LoginRateLimitService {

	private static final String KEY_PREFIX = "rateLimit:login:";
	// 1분 안에 최대 5회 시도 허용. 초과 시 1분간 차단.
	private static final int MAX_ATTEMPTS = 5;
	private static final Duration WINDOW = Duration.ofMinutes(1);

	private final StringRedisTemplate redisTemplate;

	// 시도 횟수를 증가시키고 한도를 초과하면 예외를 던진다.
	// X-Forwarded-For나 remoteAddr로 추출한 IP를 전달받는다.
	public void checkAndIncrement(String ipAddress) {
		String key = KEY_PREFIX + ipAddress;
		// increment: 키가 없으면 0으로 초기화 후 1 반환, 있으면 +1 반환 (Redis 원자적 연산).
		Long count = redisTemplate.opsForValue().increment(key);
		// 첫 요청일 때만 TTL을 설정한다. 이후 요청은 기존 TTL이 유지된다.
		if (count != null && count == 1) {
			redisTemplate.expire(key, WINDOW);
		}
		if (count != null && count > MAX_ATTEMPTS) {
			throw new AuthException(ErrorCode.TOO_MANY_REQUESTS);
		}
	}
}
