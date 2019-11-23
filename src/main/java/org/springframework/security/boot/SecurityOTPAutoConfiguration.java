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
public class SecurityOTPAutoConfiguration{
	
	@Bean
	public OTPMatchedAuthenticationEntryPoint otpMatchedAuthenticationEntryPoint() {
		return new OTPMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public OTPMatchedAuthenticationFailureHandler otpMatchedAuthenticationFailureHandler() {
		return new OTPMatchedAuthenticationFailureHandler();
	}
	 
	@Bean
	public OTPAuthenticationProvider otpAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService) {
		return new OTPAuthenticationProvider(userDetailsService);
	}
	
}
