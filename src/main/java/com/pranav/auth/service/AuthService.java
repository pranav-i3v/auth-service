package com.pranav.auth.service;

import com.pranav.auth.config.AuthProperties;
import com.pranav.auth.dto.request.LoginRequest;
import com.pranav.auth.dto.request.RegisterRequest;
import com.pranav.auth.dto.response.AccessTokenResponse;
import com.pranav.auth.dto.response.RegisterResponse;
import com.pranav.auth.dto.response.TokenResponse;
import com.pranav.auth.entity.AccountLockoutPolicy;
import com.pranav.auth.entity.PasswordChangeHistory;
import com.pranav.auth.entity.RefreshToken;
import com.pranav.auth.entity.TokenBlacklistEntry;
import com.pranav.auth.entity.User;
import com.pranav.auth.entity.enums.AccountStatus;
import com.pranav.auth.entity.enums.BlacklistReason;
import com.pranav.auth.entity.enums.LoginStatus;
import com.pranav.auth.entity.enums.PasswordChangeReason;
import com.pranav.auth.entity.enums.TokenType;
import com.pranav.auth.exception.AccountDisabledException;
import com.pranav.auth.exception.EmailAlreadyExistsException;
import com.pranav.auth.exception.InvalidCredentialsException;
import com.pranav.auth.exception.InvalidTokenException;
import com.pranav.auth.exception.UsernameAlreadyExistsException;
import com.pranav.auth.repository.PasswordChangeHistoryRepository;
import com.pranav.auth.repository.RefreshTokenRepository;
import com.pranav.auth.repository.TokenBlacklistRepository;
import com.pranav.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Orchestrates login, registration, token refresh, logout, and email verification. This is the
 * only place in the platform where credentials are checked and tokens are issued.
 */
@Slf4j
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final LoginAuditService loginAuditService;
    private final PasswordChangeHistoryRepository passwordChangeHistoryRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final AccountLockoutService accountLockoutService;
    private final AccountLockoutPolicyProvider lockoutPolicyProvider;
    private final JwtTokenService jwtTokenService;
    private final EmailService emailService;
    private final AuthProperties properties;

    public AuthService(UserRepository userRepository,
                        RefreshTokenRepository refreshTokenRepository,
                        TokenBlacklistRepository tokenBlacklistRepository,
                        LoginAuditService loginAuditService,
                        PasswordChangeHistoryRepository passwordChangeHistoryRepository,
                        PasswordEncoder passwordEncoder,
                        PasswordPolicyService passwordPolicyService,
                        AccountLockoutService accountLockoutService,
                        AccountLockoutPolicyProvider lockoutPolicyProvider,
                        JwtTokenService jwtTokenService,
                        EmailService emailService,
                        AuthProperties properties) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenBlacklistRepository = tokenBlacklistRepository;
        this.loginAuditService = loginAuditService;
        this.passwordChangeHistoryRepository = passwordChangeHistoryRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.accountLockoutService = accountLockoutService;
        this.lockoutPolicyProvider = lockoutPolicyProvider;
        this.jwtTokenService = jwtTokenService;
        this.emailService = emailService;
        this.properties = properties;
    }

    @Transactional
    public TokenResponse login(LoginRequest request, HttpServletRequest httpRequest, HttpServletResponse response) {
        String ip = clientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        Optional<User> maybeUser = userRepository.findByUsername(request.username());
        if (maybeUser.isEmpty()) {
            loginAuditService.record(null, request.username(), null, LoginStatus.FAILED_INVALID_CREDENTIALS, ip, userAgent,
                    request.deviceId(), request.deviceName(), "No such user");
            throw new InvalidCredentialsException();
        }

        User user = maybeUser.get();
        AccountLockoutPolicy policy = lockoutPolicyProvider.getActivePolicy();

        try {
            accountLockoutService.assertNotLocked(user, policy);
        } catch (Exception lockedException) {
            loginAuditService.record(user.getId(), user.getUsername(), user.getUserType().name(), LoginStatus.FAILED_ACCOUNT_LOCKED,
                    ip, userAgent, request.deviceId(), request.deviceName(), lockedException.getMessage());
            throw lockedException;
        }

        if (!user.isActive()) {
            loginAuditService.record(user.getId(), user.getUsername(), user.getUserType().name(), LoginStatus.FAILED_ACCOUNT_DISABLED,
                    ip, userAgent, request.deviceId(), request.deviceName(), "Account status: " + user.getAccountStatus());
            throw new AccountDisabledException(user.getAccountStatus().name());
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            accountLockoutService.recordFailedAttempt(user);
            loginAuditService.record(user.getId(), user.getUsername(), user.getUserType().name(), LoginStatus.FAILED_INVALID_CREDENTIALS,
                    ip, userAgent, request.deviceId(), request.deviceName(), "Password mismatch");
            throw new InvalidCredentialsException();
        }

        accountLockoutService.resetFailedAttempts(user);
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        JwtTokenService.IssuedToken accessToken = jwtTokenService.issueAccessToken(user);
        JwtTokenService.IssuedToken refreshToken = jwtTokenService.issueRefreshToken(user);
        persistRefreshToken(user, refreshToken, request.deviceId(), request.deviceName(), ip, userAgent);

        loginAuditService.record(user.getId(), user.getUsername(), user.getUserType().name(), LoginStatus.SUCCESS,
                ip, userAgent, request.deviceId(), request.deviceName(), null);

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", refreshToken.compactToken().toString())
                .httpOnly(true)
                .secure(properties.getCookie().isSecure())
                .sameSite(properties.getCookie().getSameSite())
                .path(properties.getCookie().getPath())
                .maxAge(properties.getJwt().getRefreshTokenTtl())
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        return TokenResponse.bearer(accessToken.compactToken(),
                properties.getJwt().getAccessTokenTtl().toSeconds());
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyExistsException(request.username());
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyExistsException(request.email());
        }

        AccountLockoutPolicy policy = lockoutPolicyProvider.getActivePolicy();
        passwordPolicyService.validateStrength(request.password(), policy);

        String passwordHash = passwordEncoder.encode(request.password());

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .passwordHash(passwordHash)
                .firstName(request.firstName())
                .lastName(request.lastName())
                .phoneNumber(request.phoneNumber())
                .employeeId(request.employeeId())
                .userType(request.userType())
                .accountStatus(AccountStatus.ACTIVE)
                .lastPasswordChangeAt(Instant.now())
                .passwordExpiresAt(Instant.now().plus(java.time.Duration.ofDays(policy.getPasswordMaxAgeDays())))
                .build();
        user = userRepository.save(user);

        PasswordChangeHistory historyEntry = PasswordChangeHistory.builder()
                .userId(user.getId())
                .newPasswordHash(passwordHash)
                .changeReason(PasswordChangeReason.USER_INITIATED)
                .changedBy(user.getId())
                .build();
        passwordChangeHistoryRepository.save(historyEntry);

        String verificationToken = jwtTokenService.issueEmailVerificationToken(user);
        emailService.sendVerificationEmail(user.getEmail(), user.getUsername(), verificationToken);

        log.info("Registered new user id={}, username={}, userType={}", user.getId(), user.getUsername(), user.getUserType());

        return new RegisterResponse(user.getId(), user.getUsername(), user.getEmail(), user.getUserType(),
                true, "Registration successful. Please check your email to verify your account.");
    }

    @Transactional
    public AccessTokenResponse refreshToken(String refreshTokenValue) {
        Claims claims = jwtTokenService.parseRefreshToken(refreshTokenValue);
        String jti = claims.getId();

        RefreshToken storedToken = refreshTokenRepository.findByTokenJti(jti)
                .orElseThrow(() -> new InvalidTokenException("Refresh token is unrecognized or already revoked"));

        if (!storedToken.isUsable()) {
            throw new InvalidTokenException("Refresh token has been revoked or expired");
        }
        if (!passwordEncoder.matches(sha256(refreshTokenValue), storedToken.getTokenHash())) {
            throw new InvalidTokenException("Refresh token does not match stored hash");
        }
        if (tokenBlacklistRepository.existsByTokenJti(jti)) {
            throw new InvalidTokenException("Refresh token has been revoked");
        }

        User user = userRepository.findById(storedToken.getUserId())
                .orElseThrow(() -> new InvalidTokenException("User associated with refresh token no longer exists"));

        if (!user.isActive()) {
            throw new AccountDisabledException(user.getAccountStatus().name());
        }

        JwtTokenService.IssuedToken accessToken = jwtTokenService.issueAccessToken(user);
        return AccessTokenResponse.bearer(accessToken.compactToken(), properties.getJwt().getAccessTokenTtl().toSeconds());
    }

    @Transactional
    public void logout(String refreshTokenValue) {
        Claims claims;
        try {
            claims = jwtTokenService.parseRefreshToken(refreshTokenValue);
        } catch (InvalidTokenException e) {
            // Token is already unusable - logout is idempotent, nothing further to revoke.
            log.debug("Logout called with an already-invalid refresh token: {}", e.getMessage());
            return;
        }

        String jti = claims.getId();
        Long userId = Long.parseLong(claims.getSubject());

        refreshTokenRepository.findByTokenJti(jti).ifPresent(storedToken -> {
            storedToken.setActive(false);
            storedToken.setRevokedAt(Instant.now());
            storedToken.setRevokedReason("USER_LOGOUT");
            refreshTokenRepository.save(storedToken);
        });

        if (!tokenBlacklistRepository.existsByTokenJti(jti)) {
            TokenBlacklistEntry blacklistEntry = TokenBlacklistEntry.builder()
                    .tokenJti(jti)
                    .userId(userId)
                    .tokenType(TokenType.REFRESH)
                    .blacklistReason(BlacklistReason.USER_LOGOUT)
                    .expiresAt(claims.getExpiration().toInstant())
                    .build();
            tokenBlacklistRepository.save(blacklistEntry);
        }

        loginAuditService.record(userId, null, null, LoginStatus.LOGOUT, null, null, null, null, null);
        log.info("User id={} logged out (jti={})", userId, jti);
    }

    @Transactional
    public void verifyEmail(String verificationToken) {
        Long userId = jwtTokenService.parseEmailVerificationToken(verificationToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new InvalidTokenException("User associated with verification token no longer exists"));

        if (!user.isEmailVerified()) {
            user.setEmailVerified(true);
            user.setEmailVerifiedAt(Instant.now());
            userRepository.save(user);
        }
        log.info("Email verified for user id={}", user.getId());
    }

    private void persistRefreshToken(User user, JwtTokenService.IssuedToken refreshToken, String deviceId,
                                      String deviceName, String ip, String userAgent) {
        RefreshToken entity = RefreshToken.builder()
                .userId(user.getId())
                .tokenHash(passwordEncoder.encode(sha256(refreshToken.compactToken())))
                .tokenJti(refreshToken.jti())
                .issuedAt(refreshToken.issuedAt())
                .expiresAt(refreshToken.expiresAt())
                .deviceId(deviceId)
                .deviceName(deviceName)
                .ipAddress(ip)
                .userAgent(userAgent)
                .active(true)
                .build();
        refreshTokenRepository.save(entity);
    }

    /**
     * BCrypt has a hard 72-byte input limit, but RS256 refresh tokens are far longer than that.
     * We first collapse the token to a fixed-length SHA-256 digest and then BCrypt-hash that
     * digest, satisfying both "store a BCrypt hash, never the plaintext token" and BCrypt's input
     * size constraint.
     */
    private String sha256(String value) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(hash);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String clientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
