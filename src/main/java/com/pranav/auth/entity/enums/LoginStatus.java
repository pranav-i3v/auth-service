package com.pranav.auth.entity.enums;

public enum LoginStatus {
    SUCCESS,
    FAILED_INVALID_CREDENTIALS,
    FAILED_ACCOUNT_LOCKED,
    FAILED_ACCOUNT_DISABLED,
    FAILED_MFA,
    FAILED_INVALID_TOKEN,
    LOGOUT,
    TIMEOUT
}
