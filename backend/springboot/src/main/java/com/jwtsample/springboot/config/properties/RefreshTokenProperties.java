package com.jwtsample.springboot.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.refresh-token")
public class RefreshTokenProperties {

	private String pepper;
}
