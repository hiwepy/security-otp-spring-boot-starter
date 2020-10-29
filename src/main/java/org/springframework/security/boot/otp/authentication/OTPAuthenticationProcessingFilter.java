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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

public class OTPAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
    public static final String SPRING_SECURITY_FORM_CODE_KEY = "otp";
    private String otpParameter = SPRING_SECURITY_FORM_CODE_KEY;
    private boolean postOnly = true;
	
    public OTPAuthenticationProcessingFilter(ObjectMapper objectMapper) {
    	super(new AntPathRequestMatcher("/login/otp"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        if (isPostOnly() && !WebUtils.isPostRequest(request) ) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method not supported. Request method: " + request.getMethod());
			}
			throw new AuthenticationMethodNotSupportedException(messages.getMessage(AuthResponseCode.SC_METHOD_NOT_ALLOWED.getMsgKey(), new Object[] { request.getMethod() }, 
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
	
	protected AbstractAuthenticationToken authenticationToken( String oneTimePassword ) {
		return new OTPAuthenticationToken(oneTimePassword);
	}

	public String getOtpParameter() {
		return otpParameter;
	}

	public void setOtpParameter(String otpParameter) {
		this.otpParameter = otpParameter;
	}

	public boolean isPostOnly() {
		return postOnly;
	}

	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

}