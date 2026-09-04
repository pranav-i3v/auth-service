package com.pranav.auth.exception;

public class UsernameAlreadyExistsException extends AuthServiceException {
    public UsernameAlreadyExistsException(String username) {
        super("Username '" + username + "' is already taken");
    }
}
