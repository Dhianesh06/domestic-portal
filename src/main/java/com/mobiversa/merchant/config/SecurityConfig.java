package com.mobiversa.merchant.config;

import com.mobiversa.merchant.security.JwtAuthenticationFilter;
import com.mobiversa.merchant.security.MerchantUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Spring Security 6.x Configuration for Java 21 Merchant Portal.
 * Includes CSRF protection and strict security headers for web forms.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final MerchantUserDetailsService userDetailsService;

    /**
     * Password encoder strictly using BCrypt strength 11 to match legacy hashes.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(11);
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Enable CSRF on web MVC endpoints; exempt only stateless REST endpoints (/api/**)
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/**")
                )

                // Session management: IF_REQUIRED allows HTTP sessions for Forgot Password flow
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

                // Security Headers: CSP, X-Frame-Options DENY, Cache-Control no-store, Referrer-Policy no-referrer
                .headers(headers -> headers
                        .frameOptions(frame -> frame.deny())
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; " +
                                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
                                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
                                "font-src 'self' https://fonts.gstatic.com data:; " +
                                "img-src 'self' data:; " +
                                "object-src 'none'; " +
                                "base-uri 'self';"
                        ))
                        .cacheControl(cache -> {})
                )

                // Authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Static resources and public login / forgot password pages
                        .requestMatchers(
                                "/auth/login",
                                "/auth/logout",
                                "/api/auth/**",
                                "/v1/forgot-password/**",
                                "/images/**",
                                "/css/**",
                                "/js/**",
                                "/favicon.ico"
                        ).permitAll()

                        // Protected Merchant endpoints
                        .requestMatchers("/merchant/**").hasRole("BANK_MERCHANT")

                        // All other endpoints require authentication
                        .anyRequest().authenticated()
                )

                // Custom authentication entry point redirects unauthenticated browser requests to login
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            if (request.getRequestURI().startsWith("/api/")) {
                                response.sendError(401, "Unauthorized");
                            } else {
                                response.sendRedirect("/auth/login");
                            }
                        })
                )

                // Configure Authentication Provider and JWT Filter
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
