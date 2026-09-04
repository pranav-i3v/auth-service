package com.pranav.auth.service;

import com.pranav.auth.entity.AccountLockoutPolicy;
import com.pranav.auth.entity.PasswordChangeHistory;
import com.pranav.auth.exception.PasswordReuseException;
import com.pranav.auth.exception.WeakPasswordException;
import com.pranav.auth.repository.PasswordChangeHistoryRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Enforces password strength rules and prevents password reuse, both driven by the active
 * {@link AccountLockoutPolicy} row.
 */
@Service
public class PasswordPolicyService {

    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern DIGIT = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_CHAR = Pattern.compile("[^A-Za-z0-9]");

    private final PasswordChangeHistoryRepository passwordChangeHistoryRepository;
    private final PasswordEncoder passwordEncoder;

    public PasswordPolicyService(PasswordChangeHistoryRepository passwordChangeHistoryRepository,
                                  PasswordEncoder passwordEncoder) {
        this.passwordChangeHistoryRepository = passwordChangeHistoryRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Validates the given plaintext password against the active policy.
     *
     * @throws WeakPasswordException if any rule is violated.
     */
    public void validateStrength(String rawPassword, AccountLockoutPolicy policy) {
        List<String> violations = new ArrayList<>();

        if (rawPassword == null || rawPassword.length() < policy.getPasswordMinLength()) {
            violations.add("must be at least " + policy.getPasswordMinLength() + " characters long");
        }
        if (policy.isRequireUppercase() && (rawPassword == null || !UPPERCASE.matcher(rawPassword).find())) {
            violations.add("must contain an uppercase letter");
        }
        if (policy.isRequireLowercase() && (rawPassword == null || !LOWERCASE.matcher(rawPassword).find())) {
            violations.add("must contain a lowercase letter");
        }
        if (policy.isRequireNumbers() && (rawPassword == null || !DIGIT.matcher(rawPassword).find())) {
            violations.add("must contain a number");
        }
        if (policy.isRequireSpecialChars() && (rawPassword == null || !SPECIAL_CHAR.matcher(rawPassword).find())) {
            violations.add("must contain a special character");
        }

        if (!violations.isEmpty()) {
            throw new WeakPasswordException(violations);
        }
    }

    /**
     * Ensures the new password does not match any of the user's last
     * {@code policy.passwordHistoryCount} passwords.
     *
     * @throws PasswordReuseException if a match is found.
     */
    public void assertNotReused(Long userId, String rawPassword, AccountLockoutPolicy policy) {
        List<PasswordChangeHistory> history = passwordChangeHistoryRepository.findByUserIdOrderByChangedAtDesc(
                userId, PageRequest.of(0, policy.getPasswordHistoryCount()));

        boolean reused = history.stream()
                .anyMatch(entry -> passwordEncoder.matches(rawPassword, entry.getNewPasswordHash()));

        if (reused) {
            throw new PasswordReuseException(policy.getPasswordHistoryCount());
        }
    }
}
