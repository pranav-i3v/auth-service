package com.pranav.auth.aws;

import com.pranav.auth.config.AuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Fetches and caches the RSA private key (PKCS#8 PEM) used to sign RS256 access/refresh tokens.
 * Only auth-service ever touches the private key; every other microservice only receives the
 * public key via the {@code jwt-auth} (authz-starter) library.
 */
@Slf4j
@Component
public class PrivateKeyProvider {

    private static final String PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_FOOTER = "-----END PRIVATE KEY-----";

    private final SecretsManagerClient secretsManagerClient;
    private final AuthProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ReentrantLock refreshLock = new ReentrantLock();

    private volatile RSAPrivateKey cachedKey;
    private volatile long cachedAtEpochMillis = 0L;

    public PrivateKeyProvider(SecretsManagerClient secretsManagerClient, AuthProperties properties) {
        this.secretsManagerClient = secretsManagerClient;
        this.properties = properties;
    }

    public RSAPrivateKey getPrivateKey() {
        RSAPrivateKey key = cachedKey;
        if (key != null && !isExpired()) {
            return key;
        }
        refreshLock.lock();
        try {
            if (cachedKey != null && !isExpired()) {
                return cachedKey;
            }
            return fetchAndCache();
        } finally {
            refreshLock.unlock();
        }
    }

    private boolean isExpired() {
        long ttlMillis = properties.getJwt().getPrivateKeyCacheTtl().toMillis();
        return System.currentTimeMillis() - cachedAtEpochMillis > ttlMillis;
    }

    private RSAPrivateKey fetchAndCache() {
        log.debug("Fetching JWT private key from AWS Secrets Manager (secretName={})",
                properties.getJwt().getPrivateKeySecretName());
        try {
            GetSecretValueRequest request = GetSecretValueRequest.builder()
                    .secretId(properties.getJwt().getPrivateKeySecretName())
                    .build();
            GetSecretValueResponse response = secretsManagerClient.getSecretValue(request);
            String pem = extractPem(response.secretString());
            RSAPrivateKey privateKey = parsePem(pem);

            this.cachedKey = privateKey;
            this.cachedAtEpochMillis = System.currentTimeMillis();
            log.info("Successfully loaded/refreshed JWT private key from AWS Secrets Manager");
            return privateKey;
        } catch (SecretsManagerException e) {
            if (cachedKey != null) {
                log.warn("Failed to refresh private key from AWS Secrets Manager; serving stale cached key", e);
                return cachedKey;
            }
            throw new IllegalStateException("Unable to fetch JWT private key from AWS Secrets Manager", e);
        }
    }

    private String extractPem(String secretString) {
        String fieldName = properties.getJwt().getSecretJsonField();
        if (fieldName == null || fieldName.isBlank()) {
            return secretString;
        }
        try {
            JsonNode node = objectMapper.readTree(secretString);
            JsonNode value = node.get(fieldName);
            if (value == null || value.isNull()) {
                return secretString;
            }
            return value.asText();
        } catch (Exception e) {
            return secretString;
        }
    }

    private RSAPrivateKey parsePem(String pem) {
        try {
            String sanitized = pem
                    .replace(PEM_HEADER, "")
                    .replace(PEM_FOOTER, "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(sanitized);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException e) {
            throw new IllegalStateException("Unable to parse RSA private key PEM from secret", e);
        }
    }
}
