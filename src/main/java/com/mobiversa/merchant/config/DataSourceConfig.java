package com.mobiversa.merchant.config;

import com.mobiversa.merchant.service.AwsSecretsManagerService;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.jdbc.autoconfigure.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;

/**
 * Custom DataSource configuration that integrates AWS Secrets Manager
 * with the existing HikariCP connection pool.
 */
@Slf4j
@Configuration
public class DataSourceConfig {

    @Bean
    @Primary
    @ConfigurationProperties(prefix = "spring.datasource.hikari")
    public HikariConfig hikariConfig(DataSourceProperties dataSourceProperties,
                                     AwsSecretsManagerService secretsManagerService) {
        HikariConfig config = new HikariConfig();

        // Start with base Spring DataSourceProperties (configured via application.yml or env)
        String jdbcUrl = dataSourceProperties.getUrl();
        String username = dataSourceProperties.getUsername();
        String password = dataSourceProperties.getPassword();
        String driverClassName = dataSourceProperties.getDriverClassName();

        // If AWS Secrets Manager integration is enabled, fetch credentials dynamically
        AwsSecretsManagerService.DatabaseCredentials credentials = secretsManagerService.fetchDatabaseCredentials();
        if (credentials != null) {
            log.info("Overriding database credentials using AWS Secrets Manager");
            username = credentials.getUsername();
            password = credentials.getPassword();

            if (StringUtils.hasText(credentials.getUrl())) {
                jdbcUrl = credentials.getUrl();
            }
        }

        if (StringUtils.hasText(jdbcUrl)) {
            config.setJdbcUrl(jdbcUrl);
        }
        if (StringUtils.hasText(username)) {
            config.setUsername(username);
        }
        if (StringUtils.hasText(password)) {
            config.setPassword(password);
        }
        if (StringUtils.hasText(driverClassName)) {
            config.setDriverClassName(driverClassName);
        }

        return config;
    }

    @Bean
    @Primary
    public DataSource dataSource(HikariConfig hikariConfig) {
        log.info("Initializing HikariDataSource [Pool: {}, JDBC URL: {}]",
                hikariConfig.getPoolName(), hikariConfig.getJdbcUrl());
        return new HikariDataSource(hikariConfig);
    }
}
