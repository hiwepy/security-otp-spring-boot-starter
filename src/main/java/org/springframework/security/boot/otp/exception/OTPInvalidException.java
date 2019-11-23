package org.springframework.security.boot.otp.exception;

import org.springframework.security.core.AuthenticationException;

public class OTPInvalidException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public OTPInvalidException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public OTPInvalidException(String msg, Throwable t) {
		super(msg, t);
	}

}
