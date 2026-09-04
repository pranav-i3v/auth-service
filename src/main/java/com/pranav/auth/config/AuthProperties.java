package com.pranav.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;

/**
 * Configuration properties for auth-service, bound from the {@code auth} prefix.
 */
@Data
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private String issuer = "gas-auth-service";

    @NestedConfigurationProperty
    private Jwt jwt = new Jwt();

    @NestedConfigurationProperty
    private Lockout lockout = new Lockout();

    @NestedConfigurationProperty
    private Email email = new Email();

    @NestedConfigurationProperty
    private Cookie cookie = new Cookie();

    @Data
    public static class Jwt {
        /** AWS Secrets Manager secret name/ARN holding the RSA private key (PEM, PKCS#8). */
        private String privateKeySecretName = "gas/auth/rsa-private-key";

        /** JSON field inside the secret holding the PEM private key; blank = raw secret string is the PEM. */
        private String secretJsonField = "JWT_PRIVATE_KEY";

        private String awsRegion = "";

        private Duration accessTokenTtl = Duration.ofMinutes(1);

        private Duration refreshTokenTtl = Duration.ofDays(7);

        /** How long the cached private key is kept before being re-fetched from AWS Secrets Manager. */
        private Duration privateKeyCacheTtl = Duration.ofHours(1);
    }

    @Data
    public static class Lockout {
        /**
         * Fallback lockout policy used only when no active row exists in {@code account_lockout_policy}.
         */
        private int maxFailedAttempts = 5;
        private int lockoutDurationMinutes = 30;
    }

    @Data
    public static class Email {
        private boolean enabled = true;
        private String fromAddress = "pranapatel7@gmail.com";
        private String verificationBaseUrl = "http://localhost:8081/api/v1/auth/verify-email";
        private Duration verificationTokenTtl = Duration.ofMinutes(1L);
    }

    @Data
    public static class Cookie {
        /** Browser origin permitted to send credentialed requests to this service. */
        private String allowedOrigin = "http://localhost:8081";

        /** Must be true in HTTPS deployments. */
        private boolean secure = true;

        private String sameSite = "Strict";

        /** Covers both refresh and logout endpoints. */
        private String path = "/api/v1/auth/refresh-token";
    }
}
