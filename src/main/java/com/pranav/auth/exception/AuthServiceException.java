package com.pranav.auth.exception;

/** Base class for all business-rule exceptions raised by auth-service. */
public abstract class AuthServiceException extends RuntimeException {
    protected AuthServiceException(String message) {
        super(message);
    }

    protected AuthServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}
