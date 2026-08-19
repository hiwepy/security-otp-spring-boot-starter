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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationMethodNotSupportedException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Authentication processing filter for OTP authentication.
 * <p>Intercepts authentication requests and delegates to the authentication manager.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class OTPAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
    /**
     * Constructs a new o t p authentication processing filter instance.
     *
     * @param objectMapper the object mapper
     */
    public static final String SPRING_SECURITY_FORM_CODE_KEY = "otp";
    private String otpParameter = SPRING_SECURITY_FORM_CODE_KEY;
    private boolean postOnly = true;
	
    /**
     * Constructs a new o t p authentication processing filter instance.
     *
     * @param objectMapper the object mapper
     */
    public OTPAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(PathPatternRequestMatcher.pathPattern("/login/otp"));
    }

    /**
     * attempt Authentication.
     *
     * @param request the request
     * @param response the response
     * @return the result
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        if (isPostOnly() && !WebUtils.isPostRequest(request) ) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method not supported. Request method: " + request.getMethod());
			}
			throw new AuthenticationMethodNotSupportedException(messages.getMessage(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getMsgKey(), new Object[] { request.getMethod() }, 
					"Authentication method not supported. Request method:" + request.getMethod()));
		}
        
        try {

	        String oneTimePassword = obtainOneTimePassword(request);

	        if (oneTimePassword == null) {
	        	oneTimePassword = "";
	        }
	 		
	        AbstractAuthenticationToken	authRequest = this.authenticationToken(oneTimePassword);

			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);

			return this.getAuthenticationManager().authenticate(authRequest);

		} catch (Exception e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		}

    }
    
    /**
     * obtain One Time Password.
     *
     * @param request the request
     * @return the result
     */
    protected String obtainOneTimePassword(HttpServletRequest request) {
        return request.getParameter(otpParameter);
    }

    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	/**
	 * authentication Token.
	 *
	 * @param oneTimePassword the one time password
	 * @return the result
	 */
	protected AbstractAuthenticationToken authenticationToken( String oneTimePassword ) {
		return new OTPAuthenticationToken(oneTimePassword);
	}

	/**
	 * Returns the otp parameter.
	 *
	 * @return the otp parameter
	 */
	public String getOtpParameter() {
		return otpParameter;
	}

	/**
	 * Sets the otp parameter.
	 *
	 * @param otpParameter the otp parameter
	 */
	public void setOtpParameter(String otpParameter) {
		this.otpParameter = otpParameter;
	}

	/**
	 * Returns the post only.
	 *
	 * @return the post only
	 */
	public boolean isPostOnly() {
		return postOnly;
	}

	/**
	 * Sets the post only.
	 *
	 * @param postOnly the post only
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

}
