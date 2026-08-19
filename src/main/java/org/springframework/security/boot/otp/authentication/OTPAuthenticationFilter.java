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


import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.oxerr.spring.security.otp.core.OTPAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.Assert;

/**
 * OTPAuthenticationFilter class.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class OTPAuthenticationFilter
		extends AbstractAuthenticationProcessingFilter {

	/**
	 * Constructs a new o t p authentication filter instance.
	 *
	 */
	public static final String SPRING_SECURITY_ONE_TIME_PASSWORD_KEY = "otp";

	private String oneTimePasswordParameter = SPRING_SECURITY_ONE_TIME_PASSWORD_KEY;

	/**
	 * Constructs a new o t p authentication filter instance.
	 *
	 */
	public OTPAuthenticationFilter() {
		super(PathPatternRequestMatcher.pathPattern("/**"));
	}

	/**
	 * Determines whether requires authentication.
	 *
	 * @param request the request
	 * @param response the response
	 * @return the result
	 */
	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		final Authentication auth;
		return super.requiresAuthentication(request, response)
			&& ((auth = SecurityContextHolder.getContext().getAuthentication()) == null || !auth.isAuthenticated())
			&& obtainOneTimePassword(request) != null;
	}

	/**
	 * attempt Authentication.
	 *
	 * @param request the request
	 * @param response the response
	 * @return the result
	 * @throws AuthenticationException if an error occurs
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		final String oneTimePassword = obtainOneTimePassword(request);
		final OTPAuthenticationToken authRequest = new OTPAuthenticationToken(oneTimePassword);
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	/**
	 * successful Authentication.
	 *
	 * @param request the request
	 * @param response the response
	 * @param chain the chain
	 * @param authResult the auth result
	 * @throws IOException if an error occurs
	 * @throws ServletException if an error occurs
	 */
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		SecurityContextHolder.getContext().setAuthentication(authResult);

		getRememberMeServices().loginSuccess(request, response, authResult);

		// Fire event
		if (this.eventPublisher != null) {
			eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
					authResult, this.getClass()));
		}

		chain.doFilter(request, response);
	}

	/**
	 * obtain One Time Password.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected String obtainOneTimePassword(HttpServletRequest request) {
		return request.getParameter(oneTimePasswordParameter);
	}

	/**
	 * Sets the one time password parameter.
	 *
	 * @param oneTimePasswordParameter the one time password parameter
	 */
	public void setOneTimePasswordParameter(String oneTimePasswordParameter) {
		Assert.hasText(oneTimePasswordParameter,
			"One-time password parameter must not be empty or null");
		this.oneTimePasswordParameter = oneTimePasswordParameter;
	}

}
