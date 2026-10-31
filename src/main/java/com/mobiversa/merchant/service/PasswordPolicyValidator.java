package com.mobiversa.merchant.service;

import com.mobiversa.merchant.dao.MerchantOtpDao;
import com.mobiversa.merchant.dto.MerchantInfoRecord;
import com.mobiversa.merchant.dto.MerchantRecord;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Server-side Password Policy Validator:
 * - Minimum 8 chars (configurable, default 12)
 * - Must contain uppercase letter
 * - Must contain lowercase letter
 * - Must contain digit
 * - Must contain special character
 * - Must NOT equal the merchant username (case-insensitive)
 * - Must NOT match existing password or previous 3 passwords (PASSWORD1, PASSWORD2, PASSWORD3)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordPolicyValidator {

    private final MerchantOtpDao merchantOtpDao;
    private final PasswordEncoder passwordEncoder;

    @Value("${password.policy.min-length:12}")
    private int minLength;

    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]");

    public ValidationResult validate(String newPassword, String confirmPassword, MerchantRecord merchant) {
        List<String> errors = new ArrayList<>();

        if (newPassword == null || newPassword.isBlank()) {
            errors.add("New password cannot be empty.");
            return new ValidationResult(false, errors);
        }

        if (confirmPassword == null || !newPassword.equals(confirmPassword)) {
            errors.add("Passwords do not match.");
        }

        if (newPassword.length() < minLength) {
            errors.add("Password must be at least " + minLength + " characters long.");
        }

        if (!UPPERCASE_PATTERN.matcher(newPassword).find()) {
            errors.add("Password must contain at least one uppercase letter (A-Z).");
        }

        if (!LOWERCASE_PATTERN.matcher(newPassword).find()) {
            errors.add("Password must contain at least one lowercase letter (a-z).");
        }

        if (!DIGIT_PATTERN.matcher(newPassword).find()) {
            errors.add("Password must contain at least one numeric digit (0-9).");
        }

        if (!SPECIAL_CHAR_PATTERN.matcher(newPassword).find()) {
            errors.add("Password must contain at least one special character (e.g. !@#$%^&*).");
        }

        if (merchant.getUsername() != null && newPassword.equalsIgnoreCase(merchant.getUsername().trim())) {
            errors.add("Password cannot be identical to your username.");
        }

        // Check password history (current password + PASSWORD1..3 in MERCHANT_INFO)
        if (merchant.getPassword() != null && passwordEncoder.matches(newPassword, merchant.getPassword())) {
            errors.add("New password cannot be the same as your current password.");
        }

        Optional<MerchantInfoRecord> infoRecord = merchantOtpDao.findMerchantInfoByFk(merchant.getId());
        if (infoRecord.isPresent()) {
            MerchantInfoRecord info = infoRecord.get();
            if (info.getPassword1() != null && passwordEncoder.matches(newPassword, info.getPassword1())) {
                errors.add("New password cannot be the same as any of your previous 3 passwords.");
            } else if (info.getPassword2() != null && passwordEncoder.matches(newPassword, info.getPassword2())) {
                errors.add("New password cannot be the same as any of your previous 3 passwords.");
            } else if (info.getPassword3() != null && passwordEncoder.matches(newPassword, info.getPassword3())) {
                errors.add("New password cannot be the same as any of your previous 3 passwords.");
            }
        }

        return new ValidationResult(errors.isEmpty(), errors);
    }

    public record ValidationResult(boolean valid, List<String> errorMessages) {}
}

