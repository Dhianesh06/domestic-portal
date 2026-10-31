package com.mobiversa.merchant.security;

import com.mobiversa.merchant.dao.MerchantDao;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Custom UserDetailsService dedicated to Merchant authentication.
 * Uses native SQL query via MerchantDao to enforce ACTIVE-only status check.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MerchantUserDetailsService implements UserDetailsService {

    private final MerchantDao merchantDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Authenticating merchant with username: {}", username);

        return merchantDao.findActiveMerchantByUsername(username)
                .orElseThrow(() -> {
                    log.warn("Merchant login failed: User '{}' not found or not in ACTIVE status", username);
                    return new UsernameNotFoundException("Invalid credentials or inactive account.");
                });
    }
}
