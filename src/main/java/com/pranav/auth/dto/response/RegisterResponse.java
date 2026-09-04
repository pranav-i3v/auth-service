package com.pranav.auth.dto.response;

import com.pranav.auth.entity.enums.UserType;

public record RegisterResponse(
        Long userId,
        String username,
        String email,
        UserType userType,
        boolean emailVerificationRequired,
        String message
) {
}
