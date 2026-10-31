package com.mobiversa.merchant.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mobiversa.merchant.config.AwsSecretsManagerProperties;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

import java.net.URI;

/**
 * Service responsible for securely retrieving and parsing database credentials
 * from AWS Secrets Manager during application startup.
 */
@Slf4j
@Service
public class AwsSecretsManagerService {

    private final AwsSecretsManagerProperties properties;
    private final ObjectMapper objectMapper;

    public AwsSecretsManagerService(AwsSecretsManagerProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /**
     * Value object representing retrieved database credentials.
     */
    @Getter
    public static class DatabaseCredentials {
        private final String username;
        private final String password;
        private final String url;

        public DatabaseCredentials(String username, String password, String url) {
            this.username = username;
            this.password = password;
            this.url = url;
        }
    }

    /**
     * Retrieves database credentials from AWS Secrets Manager.
     *
     * @return DatabaseCredentials containing username, password, and optionally URL.
     * @throws IllegalStateException when credentials cannot be retrieved or parsed.
     */
    public DatabaseCredentials fetchDatabaseCredentials() {
        if (!properties.isEnabled()) {
            log.info("AWS Secrets Manager integration is disabled.");
            return null;
        }

        String secretName = properties.getSecretName();
        if (!StringUtils.hasText(secretName)) {
            throw new IllegalStateException("AWS Secrets Manager is enabled, but 'aws.secretsmanager.secret-name' is not configured.");
        }

        String regionName = properties.getRegion();
        if (!StringUtils.hasText(regionName)) {
            throw new IllegalStateException("AWS Secrets Manager region is not configured.");
        }

        log.info("Fetching database secret from AWS Secrets Manager [SecretName/ARN: {}, Region: {}]", secretName, regionName);

        try (SecretsManagerClient client = buildSecretsManagerClient(regionName)) {
            GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
                    .secretId(secretName)
                    .build();

            GetSecretValueResponse response = client.getSecretValue(getSecretValueRequest);
            String secretString = response.secretString();

            if (!StringUtils.hasText(secretString)) {
                throw new IllegalStateException("Secret response from AWS Secrets Manager was empty or binary for secret: " + secretName);
            }

            return parseSecretPayload(secretString, secretName);

        } catch (ResourceNotFoundException e) {
            log.error("Secret not found in AWS Secrets Manager: {}", secretName);
            throw new IllegalStateException("Configured secret not found in AWS Secrets Manager: " + secretName, e);
        } catch (SecretsManagerException e) {
            log.error("AWS Secrets Manager error occurred: {}", e.awsErrorDetails() != null ? e.awsErrorDetails().errorMessage() : e.getMessage());
            throw new IllegalStateException("Failed to retrieve secret from AWS Secrets Manager: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error retrieving secret from AWS Secrets Manager: {}", e.getMessage());
            throw new IllegalStateException("Unexpected failure retrieving secret from AWS Secrets Manager", e);
        }
    }

    private SecretsManagerClient buildSecretsManagerClient(String regionName) {
        SecretsManagerClientBuilder builder = SecretsManagerClient.builder()
                .region(Region.of(regionName));

        // If static credentials are provided (e.g. for local dev), use them;
        // otherwise fallback to DefaultCredentialsProvider (IAM role, env vars, etc.)
        if (StringUtils.hasText(properties.getAccessKey()) && StringUtils.hasText(properties.getSecretKey())) {
            log.info("Using static AWS credentials provider for Secrets Manager");
            builder.credentialsProvider(StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(properties.getAccessKey().trim(), properties.getSecretKey().trim())
            ));
        } else {
            log.info("Using DefaultCredentialsProvider (IAM Role / AWS Environment / Instance Profile) for Secrets Manager");
            builder.credentialsProvider(DefaultCredentialsProvider.create());
        }

        return builder.build();
    }

    private DatabaseCredentials parseSecretPayload(String secretString, String secretName) {
        try {
            JsonNode rootNode = objectMapper.readTree(secretString);

            // Support standard field names (username / user, password)
            String username = null;
            if (rootNode.hasNonNull("username")) {
                username = rootNode.get("username").asText();
            } else if (rootNode.hasNonNull("user")) {
                username = rootNode.get("user").asText();
            }

            String password = null;
            if (rootNode.hasNonNull("password")) {
                password = rootNode.get("password").asText();
            }

            // Optional custom url or host/port/dbname if secret defines it
            String url = null;
            if (rootNode.hasNonNull("url")) {
                url = rootNode.get("url").asText();
            } else if (rootNode.hasNonNull("jdbcUrl")) {
                url = rootNode.get("jdbcUrl").asText();
            }

            if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
                log.error("Secret payload for '{}' is missing required fields ('username' and/or 'password')", secretName);
                throw new IllegalStateException("Secret payload is missing required 'username' or 'password' keys in secret: " + secretName);
            }

            log.info("Successfully retrieved and validated database credentials from AWS Secrets Manager for secret: {}", secretName);
            return new DatabaseCredentials(username, password, url);

        } catch (JsonProcessingException e) {
            log.error("Failed to parse secret JSON payload for secret: {}", secretName);
            throw new IllegalStateException("Failed to parse JSON payload for secret: " + secretName, e);
        }
    }
}

