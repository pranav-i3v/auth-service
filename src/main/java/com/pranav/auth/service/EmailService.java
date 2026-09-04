package com.pranav.auth.service;

import com.pranav.auth.config.AuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * Sends account verification emails. Delivery is best-effort: a failure to send must never block
 * registration, so all exceptions are caught and logged rather than propagated.
 */
@Slf4j
@Service
public class EmailService {

    private final JavaMailSender mailSender;
    private final AuthProperties properties;

    public EmailService(JavaMailSender mailSender, AuthProperties properties) {
        this.mailSender = mailSender;
        this.properties = properties;
    }

    public void sendVerificationEmail(String toAddress, String username, String verificationToken) {
        if (!properties.getEmail().isEnabled()) {
            log.debug("Email sending disabled (auth.email.enabled=false); skipping verification email for {}", toAddress);
            return;
        }
        String verificationLink = properties.getEmail().getVerificationBaseUrl() + "?token=" + verificationToken;
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(properties.getEmail().getFromAddress());
            message.setTo(toAddress);
            message.setSubject("Verify your GAS account");
            message.setText("""
                    Hi %s,

                    Please verify your email address by clicking the link below. This link expires in %d hour(s).

                    %s

                    If you did not create this account, you can safely ignore this email.
                    """.formatted(username, properties.getEmail().getVerificationTokenTtl().toHours(), verificationLink));
            mailSender.send(message);
            log.info("Verification email sent to {}", toAddress);
        } catch (Exception e) {
            log.error("Failed to send verification email to {}", toAddress, e);
            throw new RuntimeException("Failed to send verification email: " + e.getMessage());
        }
    }
}
