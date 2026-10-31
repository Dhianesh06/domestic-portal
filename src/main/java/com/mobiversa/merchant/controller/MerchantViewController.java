package com.mobiversa.merchant.controller;

import com.mobiversa.merchant.security.MerchantPrincipal;
import com.mobiversa.merchant.service.MerchantAuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Controller for rendering Thymeleaf views (Login page and Merchant Dashboard).
 */
@Controller
@RequiredArgsConstructor
public class MerchantViewController {

    private final MerchantAuthService authService;

    /**
     * Root URL redirect to login or dashboard.
     */
    @GetMapping("/")
    public String index(@AuthenticationPrincipal MerchantPrincipal principal) {
        if (principal != null) {
            return "redirect:/merchant/merchantweb";
        }
        return "redirect:/auth/login";
    }

    /**
     * Displays the Mobi-styled Login page.
     */
    @GetMapping("/auth/login")
    public String loginPage(@AuthenticationPrincipal MerchantPrincipal principal) {
        if (principal != null) {
            return "redirect:/merchant/merchantweb";
        }
        return "login";
    }

    /**
     * Protected Merchant Dashboard / Landing Page.
     * Matches legacy redirect URL: /merchant/merchantweb
     */
    @GetMapping("/merchant/merchantweb")
    public String merchantDashboard(@AuthenticationPrincipal MerchantPrincipal principal, Model model) {
        model.addAttribute("merchant", principal);
        return "dashboard";
    }

    /**
     * Logout view route.
     */
    @GetMapping("/auth/logout")
    public String logout(HttpServletResponse response) {
        authService.logout(response);
        return "redirect:/auth/login?logout=true";
    }
}

