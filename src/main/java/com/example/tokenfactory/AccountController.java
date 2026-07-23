package com.example.tokenfactory;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * The server component: it answers with the user name and the accounts
 * that Spring Security already read and validated from the incoming JWT.
 */
@RestController
public class AccountController {

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        List<Map<String, String>> accounts = jwt.getClaim("accounts");
        return Map.of("user", jwt.getClaimAsString("clientId"), "accounts", accounts);
    }
}
