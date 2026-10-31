package com.mobiversa.merchant.dao;

import com.mobiversa.merchant.dto.MerchantInfoRecord;
import com.mobiversa.merchant.dto.MerchantRecord;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Pure Data Access Object using NamedParameterJdbcTemplate for Forgot Password flow.
 * No DDL or ORM entities are used.
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public class MerchantOtpDao {

    private final NamedParameterJdbcTemplate jdbcTemplate;

    private static final String SELECT_MERCHANT_BY_USERNAME_SQL = """
            SELECT 
                ID,
                USERNAME,
                PASSWORD,
                STATUS,
                EMAIL,
                CONTACT_PERSON_NAME,
                CONTACT_PERSON_PHONE_NUMBER,
                SALUTATION,
                FIRST_NAME
            FROM MERCHANT
            WHERE UPPER(USERNAME) = UPPER(:username)
              AND STATUS = 'ACTIVE'
            """;

    private static final String SELECT_MERCHANT_INFO_BY_FK_SQL = """
            SELECT 
                ID,
                MERCHANT_FK,
                OTP_EXPIRY_TIME,
                PASSWORD1,
                PASSWORD2,
                PASSWORD3,
                SUBMERCHANT_APPROVAL_INDICATOR
            FROM MERCHANT_INFO
            WHERE MERCHANT_FK = :merchantFk
            LIMIT 1
            """;

    private static final String INSERT_MERCHANT_INFO_SQL = """
            INSERT INTO MERCHANT_INFO (
                MERCHANT_FK,
                OTP_EXPIRY_TIME,
                SUBMERCHANT_APPROVAL_INDICATOR
            ) VALUES (
                :merchantFk,
                :otpExpiryTime,
                '1'
            )
            """;

    private static final String UPDATE_MERCHANT_INFO_EXPIRY_SQL = """
            UPDATE MERCHANT_INFO
            SET OTP_EXPIRY_TIME = :otpExpiryTime
            WHERE MERCHANT_FK = :merchantFk
            """;

    private static final String CLEAR_MERCHANT_INFO_EXPIRY_SQL = """
            UPDATE MERCHANT_INFO
            SET OTP_EXPIRY_TIME = NULL
            WHERE MERCHANT_FK = :merchantFk
            """;

    private static final String UPDATE_MERCHANT_PASSWORD_SQL = """
            UPDATE MERCHANT
            SET PASSWORD = :newPassword,
                MODIFIED_DATE = NOW()
            WHERE ID = :merchantId
            """;

    private static final String ROTATE_PASSWORD_HISTORY_SQL = """
            UPDATE MERCHANT_INFO
            SET PASSWORD3 = PASSWORD2,
                PASSWORD2 = PASSWORD1,
                PASSWORD1 = :currentPassword
            WHERE MERCHANT_FK = :merchantFk
            """;

    private static final String SELECT_LATEST_OTP_BY_MOBILE_SQL = """
            SELECT OTP_DATA
            FROM MOBILE_OPT
            WHERE MOBILE_NO = :mobileNo
            ORDER BY ID DESC
            LIMIT 1
            """;

    /**
     * Parameterized query to fetch active merchant by case-insensitive username.
     */
    public Optional<MerchantRecord> findActiveMerchantByUsername(String username) {
        MapSqlParameterSource params = new MapSqlParameterSource("username", username);
        try {
            MerchantRecord record = jdbcTemplate.queryForObject(
                    SELECT_MERCHANT_BY_USERNAME_SQL,
                    params,
                    (rs, rowNum) -> MerchantRecord.builder()
                            .id(rs.getLong("ID"))
                            .username(rs.getString("USERNAME"))
                            .password(rs.getString("PASSWORD"))
                            .status(rs.getString("STATUS"))
                            .email(rs.getString("EMAIL"))
                            .contactPersonName(rs.getString("CONTACT_PERSON_NAME"))
                            .contactPersonPhoneNumber(rs.getString("CONTACT_PERSON_PHONE_NUMBER"))
                            .salutation(rs.getString("SALUTATION"))
                            .firstName(rs.getString("FIRST_NAME"))
                            .build()
            );
            return Optional.ofNullable(record);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    /**
     * Finds active merchant by ID.
     */
    public Optional<MerchantRecord> findActiveMerchantById(Long id) {
        String sql = """
                SELECT 
                    ID,
                    USERNAME,
                    PASSWORD,
                    STATUS,
                    EMAIL,
                    CONTACT_PERSON_NAME,
                    CONTACT_PERSON_PHONE_NUMBER,
                    SALUTATION,
                    FIRST_NAME
                FROM MERCHANT
                WHERE ID = :id
                  AND STATUS = 'ACTIVE'
                """;
        MapSqlParameterSource params = new MapSqlParameterSource("id", id);
        try {
            MerchantRecord record = jdbcTemplate.queryForObject(
                    sql,
                    params,
                    (rs, rowNum) -> MerchantRecord.builder()
                            .id(rs.getLong("ID"))
                            .username(rs.getString("USERNAME"))
                            .password(rs.getString("PASSWORD"))
                            .status(rs.getString("STATUS"))
                            .email(rs.getString("EMAIL"))
                            .contactPersonName(rs.getString("CONTACT_PERSON_NAME"))
                            .contactPersonPhoneNumber(rs.getString("CONTACT_PERSON_PHONE_NUMBER"))
                            .salutation(rs.getString("SALUTATION"))
                            .firstName(rs.getString("FIRST_NAME"))
                            .build()
            );
            return Optional.ofNullable(record);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    /**
     * Fetches MERCHANT_INFO record by MERCHANT_FK.
     */
    public Optional<MerchantInfoRecord> findMerchantInfoByFk(Long merchantFk) {
        MapSqlParameterSource params = new MapSqlParameterSource("merchantFk", merchantFk);
        try {
            MerchantInfoRecord record = jdbcTemplate.queryForObject(
                    SELECT_MERCHANT_INFO_BY_FK_SQL,
                    params,
                    (rs, rowNum) -> MerchantInfoRecord.builder()
                            .id(rs.getLong("ID"))
                            .merchantFk(rs.getLong("MERCHANT_FK"))
                            .otpExpiryTime(rs.getString("OTP_EXPIRY_TIME"))
                            .password1(rs.getString("PASSWORD1"))
                            .password2(rs.getString("PASSWORD2"))
                            .password3(rs.getString("PASSWORD3"))
                            .submerchantApprovalIndicator(rs.getString("SUBMERCHANT_APPROVAL_INDICATOR"))
                            .build()
            );
            return Optional.ofNullable(record);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    /**
     * Updates OTP expiry time in MERCHANT_INFO. If row does not exist, inserts a new row.
     */
    public void saveOrUpdateOtpExpiry(Long merchantFk, String formattedExpiryUtc) {
        Optional<MerchantInfoRecord> existing = findMerchantInfoByFk(merchantFk);
        if (existing.isPresent()) {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("merchantFk", merchantFk)
                    .addValue("otpExpiryTime", formattedExpiryUtc);
            jdbcTemplate.update(UPDATE_MERCHANT_INFO_EXPIRY_SQL, params);
        } else {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("merchantFk", merchantFk)
                    .addValue("otpExpiryTime", formattedExpiryUtc);
            jdbcTemplate.update(INSERT_MERCHANT_INFO_SQL, params);
        }
    }

    /**
     * Clears OTP expiry time in MERCHANT_INFO.
     */
    public void clearOtpExpiry(Long merchantFk) {
        MapSqlParameterSource params = new MapSqlParameterSource("merchantFk", merchantFk);
        jdbcTemplate.update(CLEAR_MERCHANT_INFO_EXPIRY_SQL, params);
    }

    /**
     * Retrieves the latest OTP_DATA from MOBILE_OPT by mobileNo.
     */
    public Optional<String> findLatestOtpByMobile(String mobileNo) {
        MapSqlParameterSource params = new MapSqlParameterSource("mobileNo", mobileNo);
        try {
            String otp = jdbcTemplate.queryForObject(
                    SELECT_LATEST_OTP_BY_MOBILE_SQL,
                    params,
                    String.class
            );
            return Optional.ofNullable(otp);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    /**
     * Updates MERCHANT.PASSWORD with encoded password.
     */
    public int updatePassword(Long merchantId, String encodedPassword) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("merchantId", merchantId)
                .addValue("newPassword", encodedPassword);
        return jdbcTemplate.update(UPDATE_MERCHANT_PASSWORD_SQL, params);
    }

    /**
     * Rotates PASSWORD1..3 in MERCHANT_INFO.
     */
    public int rotatePasswordHistory(Long merchantFk, String currentPasswordHash) {
        Optional<MerchantInfoRecord> existing = findMerchantInfoByFk(merchantFk);
        if (existing.isEmpty()) {
            // If no MERCHANT_INFO row exists yet, create it with PASSWORD1 set to current password
            String insertWithHistorySql = """
                    INSERT INTO MERCHANT_INFO (
                        MERCHANT_FK,
                        PASSWORD1,
                        SUBMERCHANT_APPROVAL_INDICATOR
                    ) VALUES (
                        :merchantFk,
                        :password1,
                        '1'
                    )
                    """;
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("merchantFk", merchantFk)
                    .addValue("password1", currentPasswordHash);
            return jdbcTemplate.update(insertWithHistorySql, params);
        }

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("merchantFk", merchantFk)
                .addValue("currentPassword", currentPasswordHash);
        return jdbcTemplate.update(ROTATE_PASSWORD_HISTORY_SQL, params);
    }
}

