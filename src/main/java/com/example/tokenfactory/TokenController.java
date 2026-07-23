package com.example.tokenfactory;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/** Issues an access token (short TTL) plus a refresh token, both as cookies: POST /tokens?user=alice */
@RestController
public class TokenController {

    private final TokenFactory tokenFactory;
    private final RefreshTokenStore refreshTokens;

    public TokenController(TokenFactory tokenFactory, RefreshTokenStore refreshTokens) {
        this.tokenFactory = tokenFactory;
        this.refreshTokens = refreshTokens;
    }

    @PostMapping("/tokens")
    public Map<String, Object> issue(@RequestParam("user") String user, HttpServletResponse response) {
        String accessToken = tokenFactory.createToken(user);
        String refreshToken = refreshTokens.issue(user);
        Cookies.write(response, Cookies.ACCESS_TOKEN, accessToken, tokenFactory.ttl());
        Cookies.write(response, Cookies.REFRESH_TOKEN, refreshToken, refreshTokens.ttl());
        return Map.of("token", accessToken, "expiresInSeconds", tokenFactory.ttl().toSeconds());
    }
}
