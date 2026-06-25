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

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

	private final JwtProperties jwtProperties;

	// Access Token JWT 발급 (서버에 저장하지 않음)
	public String createAccessToken(UserPrincipal userPrincipal) {
		Date now = new Date();
		Date expiry = new Date(now.getTime() + jwtProperties.getAccessExpiration());

		return Jwts.builder()
			.subject(String.valueOf(userPrincipal.getId()))
			.claim("email", userPrincipal.getEmail())
			.claim("role", userPrincipal.getRole().name())
			.issuedAt(now)
			.expiration(expiry)
			.signWith(getSigningKey())
			.compact();
	}

	public boolean validateToken(String token) {
		try {
			parseClaims(token);
			return true;
		} catch (ExpiredJwtException | MalformedJwtException | SignatureException | IllegalArgumentException exception) {
			return false;
		}
	}

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
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
