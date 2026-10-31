package com.mobiversa.merchant.service;

import com.mobiversa.merchant.dto.LoginRequest;
import com.mobiversa.merchant.dto.LoginResponse;
import com.mobiversa.merchant.security.JwtTokenProvider;
import com.mobiversa.merchant.security.MerchantPrincipal;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class MerchantAuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Authenticates merchant credentials and issues a JWT token.
     */
    public LoginResponse authenticateMerchant(LoginRequest request, HttpServletResponse response) {
        log.info("Processing merchant login for username: {}", request.getUsername());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            MerchantPrincipal principal = (MerchantPrincipal) authentication.getPrincipal();

            // Generate JWT Token
            String token = jwtTokenProvider.generateToken(principal);

            // Attach HttpOnly cookie to response for seamless Thymeleaf navigation
            jwtTokenProvider.addJwtCookie(response, token);

            log.info("Merchant login successful for user: {}", principal.getUsername());

            return LoginResponse.builder()
                    .success(true)
                    .message("Login successful")
                    .token(token)
                    .tokenType("Bearer")
                    .merchantId(principal.getId())
                    .username(principal.getUsername())
                    .businessName(principal.getBusinessName())
                    .redirectUrl("/merchant/merchantweb")
                    .build();

        } catch (BadCredentialsException | UsernameNotFoundException e) {
            log.warn("Authentication failed for merchant: {}", request.getUsername());
            throw new BadCredentialsException("Invalid username or password.");
        }
    }

    /**
     * Handles merchant logout by clearing the JWT cookie.
     */
    public void logout(HttpServletResponse response) {
        jwtTokenProvider.deleteJwtCookie(response);
    }
}

