package com.jwtsample.springboot.security.hash;

import com.jwtsample.springboot.config.properties.RefreshTokenProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

// Refresh Token 원문 대신 SHA-256 해시만 Redis에 저장하기 위한 유틸리티.
// Redis가 유출되더라도 공격자가 원문 토큰을 복원할 수 없게 한다.
@Component
@RequiredArgsConstructor
public class TokenHasher {

	private final RefreshTokenProperties refreshTokenProperties;

	// rawToken을 SHA-256(rawToken + pepper) 해시로 변환한다.
	public String hash(String rawToken) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			// pepper: 모든 토큰에 공통으로 더하는 서버 비밀값. 환경 변수로 관리한다.
			// salt(사용자별 랜덤값)와 달리 Redis에 별도 저장하지 않아도 되지만,
			// pepper가 유출되면 모든 해시를 대입 공격으로 역추적할 수 있으므로
			// 운영에서는 비밀 관리 도구(Vault 등)로 별도 보호해야 한다.
			String input = rawToken + refreshTokenProperties.getPepper();
			byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(hashBytes);
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException("SHA-256 알고리즘을 사용할 수 없습니다.", exception);
		}
	}

	// 타이밍 공격 방지를 위한 상수 시간(constant-time) 비교.
	public boolean matches(String rawToken, String storedHash) {
		String computedHash = hash(rawToken);
		// MessageDigest.isEqual: 두 배열을 항상 끝까지 비교해 실행 시간이 일정하다.
		// 일반 String.equals는 첫 불일치 지점에서 즉시 반환하므로 응답 시간 차이로
		// 해시값을 한 자리씩 추측하는 "타이밍 공격"에 취약하다.
		return MessageDigest.isEqual(
			computedHash.getBytes(StandardCharsets.UTF_8),
			storedHash.getBytes(StandardCharsets.UTF_8)
		);
	}
}
