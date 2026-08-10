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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link OTPAuthenticationToken}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("OTPAuthenticationToken Tests")
class OTPAuthenticationTokenTest {

    @Test
    @DisplayName("Instance can be created via constructor with credentials")
    void testInstantiation() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken("123456");
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Constructor with credentials sets authenticated to false")
    void testConstructorSetsAuthenticatedFalse() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken("123456");
        assertThat(instance.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("Constructor with authorities sets authenticated to true")
    void testConstructorWithAuthorities() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken(
                "principal", "123456",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(instance.isAuthenticated()).isTrue();
        assertThat(instance.getAuthorities()).hasSize(1);
    }

    @Test
    @DisplayName("getCredentials returns the credentials")
    void testGetCredentials() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken("123456");
        assertThat(instance.getCredentials()).isEqualTo("123456");
    }

    @Test
    @DisplayName("getPrincipal returns null for unauthenticated token")
    void testGetPrincipalUnauthenticated() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken("123456");
        assertThat(instance.getPrincipal()).isNull();
    }

    @Test
    @DisplayName("getPrincipal returns principal for authenticated token")
    void testGetPrincipalAuthenticated() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken(
                "principal", "123456",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(instance.getPrincipal()).isEqualTo("principal");
    }

    @Test
    @DisplayName("setAuthenticated(true) throws IllegalArgumentException")
    void testSetAuthenticatedTrueThrows() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken("123456");
        assertThatThrownBy(() -> instance.setAuthenticated(true))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("setAuthenticated(false) works")
    void testSetAuthenticatedFalse() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken("123456");
        instance.setAuthenticated(false);
        assertThat(instance.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("eraseCredentials clears the credentials")
    void testEraseCredentials() {
        OTPAuthenticationToken instance = new OTPAuthenticationToken("123456");
        instance.eraseCredentials();
        assertThat(instance.getCredentials()).isNull();
    }
}
