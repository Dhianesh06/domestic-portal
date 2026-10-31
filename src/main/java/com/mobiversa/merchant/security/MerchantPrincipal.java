package com.mobiversa.merchant.security;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * Adapter between Merchant details and Spring Security UserDetails.
 */
@Getter
@Builder
public class MerchantPrincipal implements UserDetails {

    private final Long id;
    private final String username;
    private final String password;
    private final String businessName;
    private final String email;
    private final boolean enabled;
    @Builder.Default
    private final Collection<? extends GrantedAuthority> authorities =
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_BANK_MERCHANT"));

    public MerchantPrincipal(Long id,
                             String username,
                             String password,
                             String businessName,
                             String email,
                             boolean enabled,
                             Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.businessName = businessName;
        this.email = email;
        this.enabled = enabled;
        this.authorities = authorities != null ? authorities :
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_BANK_MERCHANT"));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
