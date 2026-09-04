package com.pranav.auth.service;

import com.pranav.auth.entity.LoginAuditLog;
import com.pranav.auth.entity.enums.LoginStatus;
import com.pranav.auth.repository.LoginAuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes {@code login_audit_log} rows in their own independent transaction (REQUIRES_NEW) so
 * failure entries are durably recorded even when the calling {@code AuthService} transaction is
 * subsequently rolled back by the business exception it throws (e.g. invalid credentials).
 */
@Slf4j
@Service
public class LoginAuditService {

    private final LoginAuditLogRepository loginAuditLogRepository;

    public LoginAuditService(LoginAuditLogRepository loginAuditLogRepository) {
        this.loginAuditLogRepository = loginAuditLogRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(Long userId, String username, String userType, LoginStatus status, String ip,
                        String userAgent, String deviceId, String deviceName, String errorMessage) {
        try {
            LoginAuditLog entry = LoginAuditLog.builder()
                    .userId(userId)
                    .username(username)
                    .userType(userType)
                    .loginStatus(status)
                    .ipAddress(ip)
                    .userAgent(userAgent)
                    .deviceId(deviceId)
                    .deviceName(deviceName)
                    .errorMessage(errorMessage)
                    .build();
            loginAuditLogRepository.save(entry);
        } catch (Exception e) {
            // Audit logging must never break the caller's flow.
            log.error("Failed to write login_audit_log entry for userId={}, status={}", userId, status, e);
        }
    }
}
