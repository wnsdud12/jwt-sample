package com.jwtsample.springboot.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

// 관리자 Refresh Token Cookie 설정 (application-local.yml의 app.admin.cookie.* 에 대응).
//
// 핵심: 브라우저는 Cookie를 (name + domain + path) 조합으로 식별한다.
//   - path만 달라도 브라우저는 별개의 Cookie로 취급 → 사용자/관리자 Cookie가 서로 섞이지 않는다.
//   - name까지 다르면 path가 실수로 겹쳐도 충돌하지 않는 추가 안전망(Defense in Depth)이 생긴다.
//   - 라이브 서비스에서 name 변경은 기존 사용자 전원 로그아웃을 유발하므로,
//     새 서비스라면 처음부터 이름도 분리하고, 운영 중인 서비스라면 path 분리만으로도 충분하다.
@Getter
@Setter
@ConfigurationProperties(prefix = "app.admin.cookie")
public class AdminCookieProperties {

	private String name;
	private boolean secure;
	private String sameSite;
	private String path;
}
