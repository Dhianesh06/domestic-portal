package com.mobiversa.merchant.controller;

import com.mobiversa.merchant.dto.LoginRequest;
import com.mobiversa.merchant.dto.LoginResponse;
import com.mobiversa.merchant.service.MerchantAuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller providing JWT authentication endpoints for merchants.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class MerchantAuthController {

    private final MerchantAuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        try {
            LoginResponse loginResponse = authService.authenticateMerchant(request, response);
            return ResponseEntity.ok(loginResponse);
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("success", false, "message", ex.getMessage()));
        }
    }

    @RequestMapping(value = "/logout", method = {RequestMethod.POST, RequestMethod.GET})
    public ResponseEntity<?> logout(HttpServletResponse response) {
        authService.logout(response);
        return ResponseEntity.ok(Map.of("success", true, "message", "Logged out successfully"));
    }
}

