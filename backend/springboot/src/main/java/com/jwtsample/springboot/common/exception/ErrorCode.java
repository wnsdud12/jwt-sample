package com.jwtsample.springboot.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

	INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 올바르지 않습니다."),
	EMAIL_ALREADY_EXISTS(HttpStatus.CONFLICT, "이미 사용 중인 이메일입니다."),
	USER_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."),
	INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),
	TOKEN_REUSE_DETECTED(HttpStatus.UNAUTHORIZED, "토큰 재사용이 감지되어 Refresh Token이 무효화되었습니다."),
	CSRF_VALIDATION_FAILED(HttpStatus.FORBIDDEN, "요청이 거부되었습니다."),
	UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "인증이 필요합니다."),
	NOT_ADMIN(HttpStatus.FORBIDDEN, "관리자 권한이 없습니다."),
	VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "입력값이 올바르지 않습니다.");

	private final HttpStatus httpStatus;
	private final String message;
}
