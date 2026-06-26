package com.jwtsample.springboot.model.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
// JPA는 내부적으로 기본 생성자(인자 없는 생성자)가 필요하다.
// PROTECTED로 제한해 외부에서 new User()로 직접 생성하지 못하게 하고 @Builder만 사용하도록 강제한다.
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 100)
	private String email;

	@Column(nullable = false)
	private String password;

	@Column(nullable = false, length = 50)
	private String nickname;

	// DB에 숫자(0, 1) 대신 문자열("USER", "ADMIN")로 저장한다.
	// EnumType.ORDINAL은 Enum 순서가 바뀌면 기존 데이터와 불일치가 생기므로 STRING을 권장한다.
	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 20)
	private Role role;

	// updatable = false: 최초 생성 이후 UPDATE 쿼리에서 이 컬럼을 제외한다. 생성 시각은 변경하면 안 된다.
	@Column(nullable = false, updatable = false)
	private LocalDateTime createdAt;

	@Column(nullable = false)
	private LocalDateTime updatedAt;

	@Builder
	public User(String email, String password, String nickname, Role role) {
		this.email = email;
		this.password = password;
		this.nickname = nickname;
		this.role = role;
		this.createdAt = LocalDateTime.now();
		this.updatedAt = LocalDateTime.now();
	}
}
