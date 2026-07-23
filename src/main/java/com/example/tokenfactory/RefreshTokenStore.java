package com.example.tokenfactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Refresh tokens are opaque random strings — not JWTs — mapped to the user they were
 * issued for. They outlive the access token so a new one can be minted without a new login.
 */
@Component
public class RefreshTokenStore {

    private record Entry(String userName, Instant expiresAt) {
    }

    private final Map<String, Entry> tokens = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Duration ttl;

    public RefreshTokenStore(@Value("${demo.refresh-token-ttl}") Duration ttl) {
        this.ttl = ttl;
    }

    public Duration ttl() {
        return ttl;
    }

    public String issue(String userName) {
        byte[] value = new byte[32];
        random.nextBytes(value);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(value);
        tokens.put(token, new Entry(userName, Instant.now().plus(ttl)));
        return token;
    }

    /** The user the refresh token belongs to, or empty if it is unknown or expired. */
    public Optional<String> userFor(String token) {
        Entry entry = tokens.get(token);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.expiresAt().isBefore(Instant.now())) {
            tokens.remove(token);
            return Optional.empty();
        }
        return Optional.of(entry.userName());
    }
}
