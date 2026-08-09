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
package org.springframework.security.boot.otp.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.otp.exception.OTPExpiredException;
import org.springframework.security.boot.otp.exception.OTPIncorrectException;
import org.springframework.security.boot.otp.exception.OTPInvalidException;
import org.springframework.security.boot.otp.exception.OTPNotFoundException;
import org.springframework.security.core.AuthenticationException;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link OTPMatchedAuthenticationFailureHandler}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("OTPMatchedAuthenticationFailureHandler Tests")
class OTPMatchedAuthenticationFailureHandlerTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("supports returns true for OTPNotFoundException")
    void testSupportsNotFoundException() {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new OTPNotFoundException("not found"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for OTPExpiredException")
    void testSupportsExpiredException() {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new OTPExpiredException("expired"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for OTPInvalidException")
    void testSupportsInvalidException() {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new OTPInvalidException("invalid"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for OTPIncorrectException")
    void testSupportsIncorrectException() {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new OTPIncorrectException("incorrect"))).isTrue();
    }

    @Test
    @DisplayName("supports returns false for other exceptions")
    void testDoesNotSupportOtherExceptions() {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        AuthenticationException otherException = mock(AuthenticationException.class);
        assertThat(handler.supports(otherException)).isFalse();
    }

    @Test
    @DisplayName("onAuthenticationFailure handles OTPNotFoundException")
    void testOnFailureNotFound() throws Exception {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(printWriter);

        handler.onAuthenticationFailure(request, response, new OTPNotFoundException("not found"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("onAuthenticationFailure handles OTPExpiredException")
    void testOnFailureExpired() throws Exception {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(printWriter);

        handler.onAuthenticationFailure(request, response, new OTPExpiredException("expired"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("onAuthenticationFailure handles OTPInvalidException")
    void testOnFailureInvalid() throws Exception {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(printWriter);

        handler.onAuthenticationFailure(request, response, new OTPInvalidException("invalid"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("onAuthenticationFailure handles OTPIncorrectException")
    void testOnFailureIncorrect() throws Exception {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(printWriter);

        handler.onAuthenticationFailure(request, response, new OTPIncorrectException("incorrect"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("onAuthenticationFailure handles other exceptions with default response")
    void testOnFailureOtherException() throws Exception {
        OTPMatchedAuthenticationFailureHandler handler = new OTPMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(printWriter);

        handler.onAuthenticationFailure(request, response, mock(AuthenticationException.class));
        verify(response).setStatus(200);
    }
}
