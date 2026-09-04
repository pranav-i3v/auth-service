package com.pranav.auth.service;

import com.pranav.auth.aws.PrivateKeyProvider;
import com.pranav.auth.config.AuthProperties;
import com.pranav.auth.entity.User;
import com.pranav.auth.exception.InvalidTokenException;
import com.pranav.auth.repository.UserPermissionQueryRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Issues RS256-signed access and refresh JWTs. This is the only place in the whole GAS platform
 * that signs tokens - every other microservice only validates them via the jwt-auth
 * (authz-starter) library.
 */
@Slf4j
@Service
public class JwtTokenService {

    private final PrivateKeyProvider privateKeyProvider;
    private final AuthProperties properties;
    private final UserPermissionQueryRepository userPermissionQueryRepository;

    public JwtTokenService(PrivateKeyProvider privateKeyProvider, AuthProperties properties,
                            UserPermissionQueryRepository userPermissionQueryRepository) {
        this.privateKeyProvider = privateKeyProvider;
        this.properties = properties;
        this.userPermissionQueryRepository = userPermissionQueryRepository;
    }

    public record IssuedToken(String compactToken, String jti, Instant issuedAt, Instant expiresAt) {
    }

    /**
     * Builds a short-lived access token embedding the user's roles, permissions, region and zone
     * so downstream services can authorize requests without querying the database on every call.
     */
    public IssuedToken issueAccessToken(User user) {
        UserPermissionQueryRepository.UserClaims claims = userPermissionQueryRepository.loadClaims(user.getId());

        Instant now = Instant.now();
        Instant expiresAt = now.plus(properties.getJwt().getAccessTokenTtl());
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .subject(String.valueOf(user.getId()))
                .id(jti)
                .issuer(properties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .claim("username", user.getUsername())
                .claim("userType", user.getUserType().name())
                .claim("roles", claims.roles())
                .claim("permissions", claims.permissions())
                .claim("region", claims.regionCode())
                .claim("zone", claims.zoneCode())
                .signWith(privateKeyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .compact();

        return new IssuedToken(token, jti, now, expiresAt);
    }

    /**
     * Builds a long-lived, minimal-claim refresh token. Only {@code sub} and {@code jti} are
     * embedded; roles/permissions are re-resolved fresh whenever the refresh token is exchanged.
     */
    public IssuedToken issueRefreshToken(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(properties.getJwt().getRefreshTokenTtl());
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .subject(String.valueOf(user.getId()))
                .id(jti)
                .issuer(properties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .claim("type", "REFRESH")
                .signWith(privateKeyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .compact();

        return new IssuedToken(token, jti, now, expiresAt);
    }

    /**
     * Validates a refresh token's signature/expiry and returns its claims. The public key used
     * for verification is derived on-the-fly from the cached RSA private key (standard RSA keys
     * expose their CRT public components), so no separate public-key fetch is required here.
     */
    public Claims parseRefreshToken(String refreshToken) {
        try {
            return Jwts.parser()
                    .verifyWith(derivePublicKey())
                    .build()
                    .parseSignedClaims(refreshToken)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new InvalidTokenException("Refresh token has expired", e);
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Refresh token is invalid", e);
        }
    }

    private RSAPublicKey derivePublicKey() {
        try {
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) privateKeyProvider.getPrivateKey();
            log.info("Deriving RSA public key from private key (modulus={}, publicExponent={})",
                    privateKey.getModulus(), privateKey.getPublicExponent());
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to derive RSA public key from private key", e);
        }
    }

    /**
     * Issues a short-lived, single-purpose token used to verify a user's email address
     * (embedded in the link sent by {@link EmailService}). Kept stateless (no DB table) by
     * signing a scoped JWT rather than persisting a random opaque token.
     */
    public String issueEmailVerificationToken(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(properties.getEmail().getVerificationTokenTtl());

        return Jwts.builder()
                .subject(String.valueOf(user.getId()))
                .id(UUID.randomUUID().toString())
                .issuer(properties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .claim("purpose", "EMAIL_VERIFICATION")
                .claim("email", user.getEmail())
                .signWith(privateKeyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .header().add("typ", "JWT").and()
                .compact();
    }

    /**
     * Validates an email-verification token and returns the user id (subject) it was issued for.
     */
    public Long parseEmailVerificationToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(derivePublicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new InvalidTokenException("Email verification token has expired", e);
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidTokenException("Email verification token is invalid", e);
        }

        if (!"EMAIL_VERIFICATION".equals(claims.get("purpose", String.class))) {
            throw new InvalidTokenException("Token is not a valid email verification token");
        }
        return Long.parseLong(claims.getSubject());
    }
}
