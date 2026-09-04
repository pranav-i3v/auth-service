package com.pranav.auth.service;

import com.pranav.auth.entity.AccountLockoutPolicy;
import com.pranav.auth.repository.AccountLockoutPolicyRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Resolves the currently active {@link AccountLockoutPolicy}, falling back to sane defaults if
 * no active policy row exists yet (e.g. on a freshly provisioned database).
 */
@Slf4j
@Service
public class AccountLockoutPolicyProvider {

    private final AccountLockoutPolicyRepository repository;

    public AccountLockoutPolicyProvider(AccountLockoutPolicyRepository repository) {
        this.repository = repository;
    }

    public AccountLockoutPolicy getActivePolicy() {
        List<AccountLockoutPolicy> policies = repository.findActivePolicies(PageRequest.of(0, 1));
        if (policies.isEmpty()) {
            log.warn("No active account_lockout_policy row found; using built-in fallback defaults");
            return AccountLockoutPolicy.defaults();
        }
        return policies.get(0);
    }
}
