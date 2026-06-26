package com.jwtsample.springboot.security.jwt;

import com.jwtsample.springboot.config.properties.JwtProperties;
import com.jwtsample.springboot.security.UserPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

// Access Token(JWT) 발급·검증 담당.
// JWT는 서버에 저장하지 않고 서명(HS256)만으로 유효성을 판단한다.
// 토큰을 발급한 뒤 서버가 별도로 기억할 필요가 없어 DB·Redis 조회 없이 인증이 가능하다.
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

	private final JwtProperties jwtProperties;

	// Access Token 발급. 서버에 저장하지 않으며, 클라이언트가 매 요청마다 Authorization 헤더에 담아 보낸다.
	public String createAccessToken(UserPrincipal userPrincipal) {
		Date now = new Date();
		Date expiry = new Date(now.getTime() + jwtProperties.getAccessExpiration());

		return Jwts.builder()
			// subject: JWT 표준에서 토큰 소유자를 나타내는 필드. 문자열만 허용하므로 userId를 문자열로 변환.
			.subject(String.valueOf(userPrincipal.getId()))
			// claim: 토큰 안에 담는 추가 정보. 서버는 API 호출 시 이 정보로 DB 조회 없이 사용자를 식별한다.
			.claim("email", userPrincipal.getEmail())
			.claim("role", userPrincipal.getRole().name())
			.issuedAt(now)
			.expiration(expiry)
			.signWith(getSigningKey())
			.compact();
	}

	// 토큰의 서명과 만료 여부를 검증한다. 파싱 중 예외가 나면 유효하지 않은 토큰이다.
	public boolean validateToken(String token) {
		try {
			parseClaims(token);
			return true;
		} catch (ExpiredJwtException | MalformedJwtException | SignatureException | IllegalArgumentException exception) {
			// ExpiredJwtException  : 만료된 토큰
			// MalformedJwtException: 형식이 잘못된 토큰
			// SignatureException   : 서명이 위조된 토큰
			// IllegalArgumentException: null이거나 빈 문자열
			return false;
		}
	}

	// 이하 메서드들은 validateToken()으로 유효성을 확인한 후에만 호출해야 한다.
	public Long getUserId(String token) {
		return Long.parseLong(parseClaims(token).getSubject());
	}

	public String getEmail(String token) {
		return parseClaims(token).get("email", String.class);
	}

	public String getRole(String token) {
		return parseClaims(token).get("role", String.class);
	}

	public long getAccessExpiration() {
		return jwtProperties.getAccessExpiration();
	}

	private Claims parseClaims(String token) {
		return Jwts.parser()
			.verifyWith(getSigningKey())
			.build()
			.parseSignedClaims(token)
			.getPayload();
	}

	private SecretKey getSigningKey() {
		byte[] keyBytes = jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8);
		// JJWT가 여기서 키 길이를 검증한다. HS256 최소 256비트(32바이트) 미만이면 WeakKeyException.
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
