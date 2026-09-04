package com.pranav.auth.service;

import com.pranav.auth.dto.request.LoginRequest;
import com.pranav.auth.dto.request.RegisterRequest;
import com.pranav.auth.dto.response.RegisterResponse;
import com.pranav.auth.dto.response.TokenResponse;
import com.pranav.auth.entity.enums.UserType;
import com.pranav.auth.exception.AccountLockedException;
import com.pranav.auth.exception.EmailAlreadyExistsException;
import com.pranav.auth.exception.InvalidCredentialsException;
import com.pranav.auth.exception.UsernameAlreadyExistsException;
import com.pranav.auth.exception.WeakPasswordException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End-to-end unit test exercising register -> login -> refresh -> logout against an in-memory H2
 * database, with the AWS Secrets Manager client mocked to serve a freshly generated RSA key pair
 * (no real AWS/SMTP dependency is required to run this suite).
 */
@SpringBootTest
class AuthServiceIntegrationTest {

    @Autowired
    private AuthService authService;

    @MockitoBean
    private SecretsManagerClient secretsManagerClient;

    @Test
    void registerThenLoginThenRefreshThenLogout() throws Exception {
        mockPrivateKeySecret();

        RegisterRequest registerRequest = new RegisterRequest(
                "jdoe" + System.nanoTime(), "jdoe" + System.nanoTime() + "@example.com", "Str0ng!Passw0rd",
                "John", "Doe", "+91-9999999999", UserType.SUPPORT_STAFF, null);
        RegisterResponse registered = authService.register(registerRequest);
        assertThat(registered.userId()).isNotNull();

        LoginRequest loginRequest = new LoginRequest(registerRequest.username(), "Str0ng!Passw0rd", "device-1", "Test Device");
        HttpServletRequest httpServletRequest = new MockHttpServletRequest();
        TokenResponse tokenResponse = authService.login(loginRequest, httpServletRequest);

        assertThat(tokenResponse.accessToken()).isNotBlank();
        assertThat(tokenResponse.refreshToken()).isNotBlank();

        var accessTokenResponse = authService.refreshToken(tokenResponse.refreshToken());
        assertThat(accessTokenResponse.accessToken()).isNotBlank();

        authService.logout(tokenResponse.refreshToken());

        // Refreshing again with the now-revoked token must fail.
        assertThatThrownBy(() -> authService.refreshToken(tokenResponse.refreshToken()))
                .isInstanceOf(com.pranav.auth.exception.InvalidTokenException.class);
    }

    @Test
    void loginWithWrongPasswordFailsWithInvalidCredentials() throws Exception {
        mockPrivateKeySecret();

        RegisterRequest registerRequest = new RegisterRequest(
                "baduser" + System.nanoTime(), "baduser" + System.nanoTime() + "@example.com", "Str0ng!Passw0rd",
                "Jane", "Doe", null, UserType.CUSTOMER, null);
        authService.register(registerRequest);

        LoginRequest loginRequest = new LoginRequest(registerRequest.username(), "WrongPassword!1", null, null);
        HttpServletRequest httpServletRequest = new MockHttpServletRequest();

        assertThatThrownBy(() -> authService.login(loginRequest, httpServletRequest))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void registerWithDuplicateUsernameFails() throws Exception {
        mockPrivateKeySecret();
        String username = "dupuser" + System.nanoTime();
        RegisterRequest first = new RegisterRequest(username, username + "@example.com", "Str0ng!Passw0rd",
                "A", "B", null, UserType.CUSTOMER, null);
        authService.register(first);

        RegisterRequest second = new RegisterRequest(username, "other" + System.nanoTime() + "@example.com",
                "Str0ng!Passw0rd", "C", "D", null, UserType.CUSTOMER, null);

        assertThatThrownBy(() -> authService.register(second))
                .isInstanceOf(UsernameAlreadyExistsException.class);
    }

    @Test
    void registerWithDuplicateEmailFails() throws Exception {
        mockPrivateKeySecret();
        String email = "dupemail" + System.nanoTime() + "@example.com";
        RegisterRequest first = new RegisterRequest("user1" + System.nanoTime(), email, "Str0ng!Passw0rd",
                "A", "B", null, UserType.CUSTOMER, null);
        authService.register(first);

        RegisterRequest second = new RegisterRequest("user2" + System.nanoTime(), email, "Str0ng!Passw0rd",
                "C", "D", null, UserType.CUSTOMER, null);

        assertThatThrownBy(() -> authService.register(second))
                .isInstanceOf(EmailAlreadyExistsException.class);
    }

    @Test
    void registerWithWeakPasswordFails() throws Exception {
        mockPrivateKeySecret();
        RegisterRequest request = new RegisterRequest("weakpw" + System.nanoTime(),
                "weakpw" + System.nanoTime() + "@example.com", "weak", "A", "B", null, UserType.CUSTOMER, null);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void accountLocksAfterMaxFailedAttempts() throws Exception {
        mockPrivateKeySecret();
        RegisterRequest registerRequest = new RegisterRequest("locktest" + System.nanoTime(),
                "locktest" + System.nanoTime() + "@example.com", "Str0ng!Passw0rd", "A", "B", null,
                UserType.CUSTOMER, null);
        authService.register(registerRequest);

        LoginRequest badLogin = new LoginRequest(registerRequest.username(), "WrongPassword!1", null, null);
        HttpServletRequest httpServletRequest = new MockHttpServletRequest();

        for (int i = 0; i < 5; i++) {
            try {
                authService.login(badLogin, httpServletRequest);
            } catch (InvalidCredentialsException ignored) {
                // expected for each of the first 5 attempts
            }
        }

        assertThatThrownBy(() -> authService.login(badLogin, httpServletRequest))
                .isInstanceOf(AccountLockedException.class);
    }

    private void mockPrivateKeySecret() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----";

        GetSecretValueResponse response = GetSecretValueResponse.builder()
                .secretString(pem)
                .build();

        Mockito.when(secretsManagerClient.getSecretValue(Mockito.any(GetSecretValueRequest.class)))
                .thenReturn(response);
    }
}
