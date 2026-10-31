package com.mobiversa.merchant.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mobiversa.merchant.config.AwsSecretsManagerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AwsSecretsManagerServiceTest {

    private AwsSecretsManagerProperties properties;
    private ObjectMapper objectMapper;
    private AwsSecretsManagerService service;

    @BeforeEach
    void setUp() {
        properties = new AwsSecretsManagerProperties();
        objectMapper = new ObjectMapper();
        service = new AwsSecretsManagerService(properties, objectMapper);
    }

    @Test
    @DisplayName("Should return null when AWS Secrets Manager is disabled")
    void shouldReturnNullWhenDisabled() {
        properties.setEnabled(false);
        AwsSecretsManagerService.DatabaseCredentials credentials = service.fetchDatabaseCredentials();
        assertNull(credentials);
    }

    @Test
    @DisplayName("Should fail fast when enabled but secret name is blank")
    void shouldFailWhenSecretNameIsMissing() {
        properties.setEnabled(true);
        properties.setSecretName("");
        properties.setRegion("ap-southeast-1");

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> {
            service.fetchDatabaseCredentials();
        });

        assertTrue(exception.getMessage().contains("aws.secretsmanager.secret-name"));
    }

    @Test
    @DisplayName("Should fail fast when enabled with invalid AWS credentials or unreachable secret")
    void shouldFailWhenSecretCannotBeFetched() {
        properties.setEnabled(true);
        properties.setSecretName("non-existent-secret-id");
        properties.setRegion("us-east-1");
        properties.setAccessKey("AKIAIOSFODNN7EXAMPLE");
        properties.setSecretKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

        assertThrows(IllegalStateException.class, () -> {
            service.fetchDatabaseCredentials();
        });
    }
}

