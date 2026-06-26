package com.jwtsample.springboot.common.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

// 애플리케이션 전역에서 발생하는 예외를 일관된 JSON 형식으로 변환하는 핸들러.
// @RestControllerAdvice: 모든 @RestController에서 던진 예외를 이 클래스가 가로채 처리한다.
// 각 @ExceptionHandler가 특정 예외 타입을 받아 적절한 HTTP 상태코드와 메시지를 반환한다.
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

	// AuthException(인증/인가 관련 예외)을 적절한 HTTP 상태코드와 메시지로 변환한다.
	@ExceptionHandler(AuthException.class)
	public ResponseEntity<ErrorResponse> handleAuthException(AuthException exception) {
		ErrorCode errorCode = exception.getErrorCode();
		return ResponseEntity
			.status(errorCode.getHttpStatus())
			.body(ErrorResponse.of(errorCode));
	}

	// @Valid 검증 실패 시 발생하는 예외를 처리한다.
	// 여러 필드에 에러가 있으면 메시지를 이어붙여 하나의 응답으로 반환한다.
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ErrorResponse> handleValidationException(MethodArgumentNotValidException exception) {
		String message = exception.getBindingResult().getFieldErrors().stream()
			.map(FieldError::getDefaultMessage)
			.collect(Collectors.joining(", "));

		ErrorResponse response = ErrorResponse.builder()
			.code(ErrorCode.VALIDATION_FAILED.name())
			.message(message)
			.timestamp(java.time.LocalDateTime.now())
			.build();

		return ResponseEntity.badRequest().body(response);
	}

	// 예상하지 못한 모든 예외를 여기서 잡는다.
	// 상세 원인은 서버 로그에만 기록하고, 클라이언트에는 일반 메시지만 반환한다.
	// → 스택 트레이스나 내부 구조가 외부에 노출되면 공격자에게 힌트가 된다.
	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponse> handleUnexpectedException(Exception exception) {
		log.error("Unexpected error", exception);
		return ResponseEntity
			.status(ErrorCode.INTERNAL_SERVER_ERROR.getHttpStatus())
			.body(ErrorResponse.of(ErrorCode.INTERNAL_SERVER_ERROR));
	}
}
