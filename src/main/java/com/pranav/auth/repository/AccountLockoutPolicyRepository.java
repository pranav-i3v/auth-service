package com.pranav.auth.repository;

import com.pranav.auth.entity.AccountLockoutPolicy;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface AccountLockoutPolicyRepository extends JpaRepository<AccountLockoutPolicy, Long> {

    @Query("SELECT p FROM AccountLockoutPolicy p WHERE p.active = true ORDER BY p.updatedAt DESC")
    List<AccountLockoutPolicy> findActivePolicies(Pageable pageable);
}
