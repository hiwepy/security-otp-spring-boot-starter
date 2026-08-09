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
package org.springframework.security.boot.otp.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for OTP exception classes.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("OTP Exception Tests")
class OTPExceptionTest {

    @Test
    @DisplayName("OTPExpiredException can be created with message")
    void testExpiredExceptionWithMessage() {
        OTPExpiredException exception = new OTPExpiredException("OTP expired");
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("OTP expired");
    }

    @Test
    @DisplayName("OTPExpiredException can be created with message and cause")
    void testExpiredExceptionWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OTPExpiredException exception = new OTPExpiredException("OTP expired", cause);
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("OTP expired");
        assertThat(exception.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("OTPIncorrectException can be created with message")
    void testIncorrectExceptionWithMessage() {
        OTPIncorrectException exception = new OTPIncorrectException("OTP incorrect");
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("OTP incorrect");
    }

    @Test
    @DisplayName("OTPIncorrectException can be created with message and cause")
    void testIncorrectExceptionWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OTPIncorrectException exception = new OTPIncorrectException("OTP incorrect", cause);
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("OTP incorrect");
        assertThat(exception.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("OTPInvalidException can be created with message")
    void testInvalidExceptionWithMessage() {
        OTPInvalidException exception = new OTPInvalidException("OTP invalid");
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("OTP invalid");
    }

    @Test
    @DisplayName("OTPInvalidException can be created with message and cause")
    void testInvalidExceptionWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OTPInvalidException exception = new OTPInvalidException("OTP invalid", cause);
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("OTP invalid");
        assertThat(exception.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("OTPNotFoundException can be created with message")
    void testNotFoundExceptionWithMessage() {
        OTPNotFoundException exception = new OTPNotFoundException("OTP not found");
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("OTP not found");
    }

    @Test
    @DisplayName("OTPNotFoundException can be created with message and cause")
    void testNotFoundExceptionWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        OTPNotFoundException exception = new OTPNotFoundException("OTP not found", cause);
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("OTP not found");
        assertThat(exception.getCause()).isSameAs(cause);
    }
}
