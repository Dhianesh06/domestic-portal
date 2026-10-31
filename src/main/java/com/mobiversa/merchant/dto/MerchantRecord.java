package com.mobiversa.merchant.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Read-only record of Merchant details retrieved from MySQL for Forgot Password flow.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MerchantRecord {
    private Long id;
    private String username;
    private String password;
    private String status;
    private String email;
    private String contactPersonName;
    private String contactPersonPhoneNumber;
    private String salutation;
    private String firstName;
}

