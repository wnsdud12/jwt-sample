package com.jwtsample.springboot.security.hash;

import com.jwtsample.springboot.config.properties.RefreshTokenProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Component
@RequiredArgsConstructor
public class TokenHasher {

	private final RefreshTokenProperties refreshTokenProperties;

	// Refresh Token 원문 대신 SHA-256 + pepper 해시만 Redis에 저장
	public String hash(String rawToken) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			String input = rawToken + refreshTokenProperties.getPepper();
			byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(hashBytes);
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException("SHA-256 알고리즘을 사용할 수 없습니다.", exception);
		}
	}

	// 타이밍 공격 방지를 위한 상수 시간 비교
	public boolean matches(String rawToken, String storedHash) {
		String computedHash = hash(rawToken);
		return MessageDigest.isEqual(
			computedHash.getBytes(StandardCharsets.UTF_8),
			storedHash.getBytes(StandardCharsets.UTF_8)
		);
	}
}
