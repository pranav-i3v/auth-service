package com.pranav.auth.service;

import com.pranav.auth.entity.AccountLockoutPolicy;
import com.pranav.auth.entity.User;
import com.pranav.auth.entity.enums.LoginStatus;
import com.pranav.auth.exception.AccountLockedException;
import com.pranav.auth.repository.LoginAuditLogRepository;
import com.pranav.auth.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Implements the "lock account after N failed attempts for M minutes" policy without requiring a
 * dedicated lockout-timestamp column on {@code users}: the lockout window is derived from
 * {@code users.failed_login_attempts} together with the timestamp of the most recent failed
 * attempt recorded in {@code login_audit_log}.
 */
@Slf4j
@Service
public class AccountLockoutService {

    private static final List<LoginStatus> FAILURE_STATUSES = List.of(
            LoginStatus.FAILED_INVALID_CREDENTIALS, LoginStatus.FAILED_ACCOUNT_LOCKED);

    private final UserRepository userRepository;
    private final LoginAuditLogRepository loginAuditLogRepository;

    public AccountLockoutService(UserRepository userRepository, LoginAuditLogRepository loginAuditLogRepository) {
        this.userRepository = userRepository;
        this.loginAuditLogRepository = loginAuditLogRepository;
    }

    /**
     * Throws {@link AccountLockedException} if the account is currently within its lockout
     * window; otherwise does nothing (including silently resetting a stale attempt counter once
     * the lockout window has elapsed).
     */
    public void assertNotLocked(User user, AccountLockoutPolicy policy) {
        if (user.getFailedLoginAttempts() < policy.getMaxFailedAttempts()) {
            return;
        }

        Optional<Instant> lastFailure = loginAuditLogRepository.findLastFailureTimestamp(user.getId(), FAILURE_STATUSES);
        if (lastFailure.isEmpty()) {
            return;
        }

        Instant lockoutExpiresAt = lastFailure.get().plus(Duration.ofMinutes(policy.getLockoutDurationMinutes()));
        if (Instant.now().isBefore(lockoutExpiresAt)) {
            throw new AccountLockedException(Duration.between(Instant.now(), lockoutExpiresAt));
        }

        // Lockout window has elapsed - reset the counter so the user can try again.
        user.setFailedLoginAttempts(0);
        userRepository.save(user);
    }

    /**
     * Runs in its own, independent transaction (REQUIRES_NEW) so the incremented counter survives
     * even when the calling {@code login()} transaction is subsequently rolled back by the
     * {@link com.pranav.auth.exception.InvalidCredentialsException} it throws.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailedAttempt(User user) {
        userRepository.findById(user.getId()).ifPresent(managed -> {
            managed.setFailedLoginAttempts(managed.getFailedLoginAttempts() + 1);
            userRepository.save(managed);
        });
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void resetFailedAttempts(User user) {
        userRepository.findById(user.getId()).ifPresent(managed -> {
            if (managed.getFailedLoginAttempts() != 0) {
                managed.setFailedLoginAttempts(0);
                userRepository.save(managed);
            }
        });
    }
}
