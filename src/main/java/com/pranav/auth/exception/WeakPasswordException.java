package com.pranav.auth.exception;

import java.util.List;

public class WeakPasswordException extends AuthServiceException {
    public WeakPasswordException(List<String> violations) {
        super("Password does not meet policy requirements: " + String.join("; ", violations));
    }
}
