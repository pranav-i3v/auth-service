package com.pranav.auth.repository;

import com.pranav.auth.entity.LoginAuditLog;
import com.pranav.auth.entity.enums.LoginStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface LoginAuditLogRepository extends JpaRepository<LoginAuditLog, Long> {

    @Query("SELECT MAX(l.loggedAt) FROM LoginAuditLog l WHERE l.userId = :userId AND l.loginStatus IN :statuses")
    Optional<Instant> findLastFailureTimestamp(@Param("userId") Long userId, @Param("statuses") List<LoginStatus> statuses);
}
