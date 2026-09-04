package com.pranav.auth.exception;

public class PasswordReuseException extends AuthServiceException {
    public PasswordReuseException(int historyCount) {
        super("New password must not match any of your last " + historyCount + " passwords");
    }
}
