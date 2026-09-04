package com.pranav.auth.dto.response;

public record TokenResponse(
        String accessToken,
        String tokenType,
        Long expiresInSeconds
) {
    public static TokenResponse bearer(String accessToken, Long expiresInSeconds) {
        return new TokenResponse(accessToken, "Bearer", expiresInSeconds);
    }
}
