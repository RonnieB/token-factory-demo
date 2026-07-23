package com.example.tokenfactory;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

/**
 * Mints a fresh access token from the refresh token cookie, then 302s back to wherever the
 * caller was headed. If the refresh token is missing or expired there is nothing to refresh,
 * so the caller is genuinely unauthenticated and must ask /tokens for a new pair.
 */
@RestController
public class RefreshController {

    private final TokenFactory tokenFactory;
    private final RefreshTokenStore refreshTokens;

    public RefreshController(TokenFactory tokenFactory, RefreshTokenStore refreshTokens) {
        this.tokenFactory = tokenFactory;
        this.refreshTokens = refreshTokens;
    }

    @GetMapping("/refresh")
    public ResponseEntity<Void> refresh(@RequestParam(value = "redirect", defaultValue = "/me") String redirect,
                                        HttpServletRequest request, HttpServletResponse response) {
        return Cookies.read(request, Cookies.REFRESH_TOKEN)
                .flatMap(refreshTokens::userFor)
                .map(user -> {
                    Cookies.write(response, Cookies.ACCESS_TOKEN, tokenFactory.createToken(user), tokenFactory.ttl());
                    return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(redirect)).<Void>build();
                })
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }
}
