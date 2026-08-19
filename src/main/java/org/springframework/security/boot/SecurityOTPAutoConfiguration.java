package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.otp.authentication.OTPAuthenticationProvider;
import org.springframework.security.boot.otp.authentication.OTPMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.otp.authentication.OTPMatchedAuthenticationFailureHandler;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityOTPProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityOTPProperties.class })
/**
 * Auto-configuration for SecurityOTP integration.
 * <p>Registers the necessary beans when the feature is enabled.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class SecurityOTPAutoConfiguration{
	
	/**
	 * otp Matched Authentication Entry Point.
	 *
	 * @return the result
	 */
	@Bean
	public OTPMatchedAuthenticationEntryPoint otpMatchedAuthenticationEntryPoint() {
		return new OTPMatchedAuthenticationEntryPoint();
	}
	
	/**
	 * otp Matched Authentication Failure Handler.
	 *
	 * @return the result
	 */
	@Bean
	public OTPMatchedAuthenticationFailureHandler otpMatchedAuthenticationFailureHandler() {
		return new OTPMatchedAuthenticationFailureHandler();
	}
	 
	/**
	 * otp Authentication Provider.
	 *
	 * @param userDetailsService the user details service
	 * @return the result
	 */
	@Bean
	public OTPAuthenticationProvider otpAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService) {
		return new OTPAuthenticationProvider(userDetailsService);
	}
	
}
