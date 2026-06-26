package com.jwtsample.springboot.model.user;

import com.jwtsample.springboot.common.exception.AuthException;
import com.jwtsample.springboot.common.exception.ErrorCode;
import com.jwtsample.springboot.view.auth.SignupRequest;
import com.jwtsample.springboot.view.user.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@Transactional
	public UserResponse signup(SignupRequest request) {
		if (userRepository.existsByEmail(request.getEmail())) {
			throw new AuthException(ErrorCode.EMAIL_ALREADY_EXISTS);
		}

		User user = User.builder()
			.email(request.getEmail())
			// encode("1234") 호출 결과 예시:
			//   $2a$10$N9qo8uLOickgx2ZMRZoMye IjZAgcfl7p92ldGxad68LJZdL17lhWy
			//           ^^^^^^^^^^^^^^^^^^^^^^^^ ← 매번 다른 랜덤 salt
			// salt가 결과 문자열 안에 포함되므로 별도로 저장하거나 관리할 필요 없다.
			.password(passwordEncoder.encode(request.getPassword()))
			.nickname(request.getNickname())
			.role(Role.USER)
			.build();

		User savedUser = userRepository.save(user);
		return UserResponse.from(savedUser);
	}

	public UserResponse getUserById(Long userId) {
		User user = userRepository.findById(userId)
			.orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
		return UserResponse.from(user);
	}

	public User findByEmail(String email) {
		return userRepository.findByEmail(email)
			.orElseThrow(() -> new AuthException(ErrorCode.INVALID_CREDENTIALS));
	}

	public User getUserEntityById(Long userId) {
		return userRepository.findById(userId)
			.orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
	}

	// JpaRepository가 기본 제공하는 findAll()로 전체 목록을 조회한다.
	public List<UserResponse> getAllUsers() {
		return userRepository.findAll().stream()
			.map(UserResponse::from)
			.collect(Collectors.toList());
	}
}
