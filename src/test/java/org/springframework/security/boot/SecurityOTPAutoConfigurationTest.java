/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link SecurityOTPAutoConfiguration}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecurityOTPAutoConfiguration Tests")
class SecurityOTPAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner();

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        SecurityOTPAutoConfiguration configuration = new SecurityOTPAutoConfiguration();
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("OTPMatchedAuthenticationEntryPoint bean can be created")
    void testEntryPointBeanCreation() {
        SecurityOTPAutoConfiguration configuration = new SecurityOTPAutoConfiguration();
        assertThat(configuration.otpMatchedAuthenticationEntryPoint()).isNotNull();
    }

    @Test
    @DisplayName("OTPMatchedAuthenticationFailureHandler bean can be created")
    void testFailureHandlerBeanCreation() {
        SecurityOTPAutoConfiguration configuration = new SecurityOTPAutoConfiguration();
        assertThat(configuration.otpMatchedAuthenticationFailureHandler()).isNotNull();
    }

    @Test
    @DisplayName("OTPAuthenticationProvider bean can be created with mock UserDetailsServiceAdapter")
    void testProviderBeanCreation() {
        SecurityOTPAutoConfiguration configuration = new SecurityOTPAutoConfiguration();
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        assertThat(configuration.otpAuthenticationProvider(userDetailsService)).isNotNull();
    }

    @Test
    @DisplayName("PREFIX constant has expected value")
    void testPrefixConstant() {
        assertThat(SecurityOTPProperties.PREFIX).isEqualTo("spring.security.otp");
    }
}
