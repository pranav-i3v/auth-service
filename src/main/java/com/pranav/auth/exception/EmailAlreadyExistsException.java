package com.pranav.auth.exception;

public class EmailAlreadyExistsException extends AuthServiceException {
    public EmailAlreadyExistsException(String email) {
        super("An account with email '" + email + "' already exists");
    }
}
