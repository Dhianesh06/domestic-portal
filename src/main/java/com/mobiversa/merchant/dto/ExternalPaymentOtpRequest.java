package com.mobiversa.merchant.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExternalPaymentOtpRequest {
    private String service;
    private String username;
    private String mobileNo;
    private String email;
    private String salutation;
    private String firstName;
}

