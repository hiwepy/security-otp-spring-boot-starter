package org.springframework.security.boot.otp.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Exception thrown for OTPExpired errors.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class OTPExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public OTPExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public OTPExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
