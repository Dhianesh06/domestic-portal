package com.mobiversa.merchant.dao;

import com.mobiversa.merchant.security.MerchantPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Data Access Object executing native SQL queries against the legacy MERCHANT table.
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public class MerchantDao {

    private final NamedParameterJdbcTemplate jdbcTemplate;

    private static final String SELECT_ACTIVE_MERCHANT_SQL = """
            SELECT
                ID,
                USERNAME,
                PASSWORD,
                STATUS,
                BUSINESS_NAME,
                TRADING_NAME,
                EMAIL,
                ENABLED
            FROM MERCHANT
            WHERE USERNAME = :username
              AND STATUS = 'ACTIVE'
              AND UPPER(ENBL_PAYOUT) <> 'YES'
              AND ENABLE_PORTAL = 1
            """;

    /**
     * Finds an active merchant by username directly via native SQL.
     *
     * @param username the merchant login username
     * @return Optional of MerchantPrincipal if found and active
     */
    public Optional<MerchantPrincipal> findActiveMerchantByUsername(String username) {
        log.debug("Executing native query to fetch active merchant: {}", username);

        MapSqlParameterSource params = new MapSqlParameterSource("username", username);

        try {
            MerchantPrincipal principal = jdbcTemplate.queryForObject(
                    SELECT_ACTIVE_MERCHANT_SQL,
                    params,
                    (rs, rowNum) -> {
                        String businessName = rs.getString("BUSINESS_NAME");
                        if (businessName == null || businessName.isBlank()) {
                            businessName = rs.getString("TRADING_NAME");
                        }

                        // Enabled flag defaults to true if null in DB
                        boolean enabled = true;
                        Object enabledVal = rs.getObject("ENABLED");
                        if (enabledVal instanceof Boolean b) {
                            enabled = b;
                        } else if (enabledVal instanceof Number n) {
                            enabled = n.intValue() == 1;
                        }

                        return MerchantPrincipal.builder()
                                .id(rs.getLong("ID"))
                                .username(rs.getString("USERNAME"))
                                .password(rs.getString("PASSWORD"))
                                .businessName(businessName)
                                .email(rs.getString("EMAIL"))
                                .enabled(enabled)
                                .build();
                    }
            );

            return Optional.ofNullable(principal);
        } catch (EmptyResultDataAccessException e) {
            log.debug("No active merchant found with username: {}", username);
            return Optional.empty();
        }
    }
}

