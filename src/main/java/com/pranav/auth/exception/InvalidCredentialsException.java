package com.pranav.auth.exception;

public class InvalidCredentialsException extends AuthServiceException {
    public InvalidCredentialsException() {
        super("Invalid username or password");
    }
}
