package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityOTPProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityOTPProperties {

	public static final String PREFIX = "spring.security.otp";

	/** Whether Enable JWT Authentication. */
	private boolean enabled = false;

}
