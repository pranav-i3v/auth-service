package com.pranav.auth.repository;

import com.pranav.auth.entity.PasswordChangeHistory;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PasswordChangeHistoryRepository extends JpaRepository<PasswordChangeHistory, Long> {

    List<PasswordChangeHistory> findByUserIdOrderByChangedAtDesc(Long userId, Pageable pageable);
}
