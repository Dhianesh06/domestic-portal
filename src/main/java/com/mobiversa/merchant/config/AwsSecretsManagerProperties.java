package com.mobiversa.merchant.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration properties for AWS Secrets Manager integration.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "aws.secretsmanager")
public class AwsSecretsManagerProperties {

    /**
     * Whether AWS Secrets Manager integration is enabled.
     * When true, database credentials will be retrieved from AWS Secrets Manager.
     */
    private boolean enabled = false;

    /**
     * The AWS region (e.g. ap-southeast-1, us-east-1).
     */
    private String region = "ap-southeast-1";

    /**
     * The secret name or ARN containing the database credentials.
     */
    private String secretName;

    /**
     * Optional static AWS Access Key ID (primarily for local development).
     * In deployed environments (dev, uat, prod), IAM roles should be preferred.
     */
    private String accessKey;

    /**
     * Optional static AWS Secret Access Key (primarily for local development).
     */
    private String secretKey;
}

