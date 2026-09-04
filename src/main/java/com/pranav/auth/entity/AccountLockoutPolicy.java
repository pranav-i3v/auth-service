package com.pranav.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * Maps to the {@code account_lockout_policy} table - configurable password/lockout rules.
 * auth-service loads the active policy at login/register/password-change time rather than
 * hard-coding thresholds.
 */
@Entity
@Table(name = "account_lockout_policy")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountLockoutPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "policy_name", nullable = false, length = 100)
    private String policyName;

    @Column(name = "max_failed_attempts", nullable = false)
    private int maxFailedAttempts;

    @Column(name = "lockout_duration_minutes", nullable = false)
    private int lockoutDurationMinutes;

    @Column(name = "password_min_length", nullable = false)
    private int passwordMinLength;

    @Column(name = "password_max_age_days", nullable = false)
    private int passwordMaxAgeDays;

    @Column(name = "password_history_count", nullable = false)
    private int passwordHistoryCount;

    @Column(name = "require_uppercase", nullable = false)
    private boolean requireUppercase;

    @Column(name = "require_lowercase", nullable = false)
    private boolean requireLowercase;

    @Column(name = "require_numbers", nullable = false)
    private boolean requireNumbers;

    @Column(name = "require_special_chars", nullable = false)
    private boolean requireSpecialChars;

    @Column(name = "require_mfa_for_admin", nullable = false)
    private boolean requireMfaForAdmin;

    @Column(name = "is_active", nullable = false)
    private boolean active;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /** Sensible defaults used only if no active policy row exists in the database. */
    public static AccountLockoutPolicy defaults() {
        return AccountLockoutPolicy.builder()
                .policyName("DEFAULT_FALLBACK")
                .maxFailedAttempts(5)
                .lockoutDurationMinutes(30)
                .passwordMinLength(8)
                .passwordMaxAgeDays(90)
                .passwordHistoryCount(5)
                .requireUppercase(true)
                .requireLowercase(true)
                .requireNumbers(true)
                .requireSpecialChars(true)
                .requireMfaForAdmin(true)
                .active(true)
                .build();
    }
}
