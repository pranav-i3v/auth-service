package com.pranav.auth.exception;

public class AccountDisabledException extends AuthServiceException {
    public AccountDisabledException(String status) {
        super("Account is not active (status: " + status + ")");
    }
}
