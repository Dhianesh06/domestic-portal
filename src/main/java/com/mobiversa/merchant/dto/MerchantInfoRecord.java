package com.mobiversa.merchant.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Record representing relevant columns of MERCHANT_INFO table.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MerchantInfoRecord {
    private Long id;
    private Long merchantFk;
    private String otpExpiryTime;
    private String password1;
    private String password2;
    private String password3;
    private String submerchantApprovalIndicator;
}

