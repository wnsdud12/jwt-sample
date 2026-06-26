package com.jwtsample.springboot.model.auth;

import com.jwtsample.springboot.view.auth.AccessTokenResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;

// AuthService와 AdminAuthService 두 곳에서 공통으로 사용하는 반환 타입.
// Access Token(JSON)과 Refresh Cookie를 함께 반환해야 하는데 메서드는 값을 하나만 반환할 수 있어 record로 묶는다.
// refreshCookie가 null이면 grace 중복 요청으로 Cookie 갱신 없이 Access Token만 재발급한 경우다.
public record TokenWithCookie(AccessTokenResponse accessToken, @Nullable ResponseCookie refreshCookie) {
}
