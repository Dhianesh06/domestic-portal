package com.mobiversa.merchant.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    private boolean success;
    private String message;
    private String token;
    private String tokenType;
    private Long merchantId;
    private String username;
    private String businessName;
    private String redirectUrl;
}

