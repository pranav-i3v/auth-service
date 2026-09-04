package com.pranav.auth.exception;

import java.time.Duration;

public class AccountLockedException extends AuthServiceException {

    public AccountLockedException(Duration remaining) {
        super("Account is locked due to too many failed login attempts. Try again in "
                + Math.max(1, remaining.toMinutes()) + " minute(s)");
    }
}
