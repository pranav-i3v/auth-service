package com.pranav.auth.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;

@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AwsConfig {

    @Bean
    public SecretsManagerClient secretsManagerClient(AuthProperties properties) {
        String region = properties.getJwt().getAwsRegion();
        SecretsManagerClientBuilder builder = SecretsManagerClient.builder();
        if (region != null && !region.isBlank()) {
            builder.region(Region.of(region));
        }
        return builder.build();
    }
}
