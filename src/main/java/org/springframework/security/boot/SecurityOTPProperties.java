package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityOTPProperties.PREFIX)
@Getter
@Setter
@ToString
/**
 * Configuration properties.
 * <p>Binds to the application property prefix and provides
 * customizable settings.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class SecurityOTPProperties {

	public static final String PREFIX = "spring.security.otp";

	/** Whether Enable JWT Authentication. */
	private boolean enabled = false;

}
