package com.example.tokenfactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Creates a signed JWT for a given user name.
 * The token carries a {@code clientId} claim (the user name) and two accounts
 * with a random 6-digit accountId each.
 */
@Component
public class TokenFactory {

    private static final int ACCOUNTS_PER_TOKEN = 2;

    private final JwtEncoder encoder;
    private final SecureRandom random = new SecureRandom();
    private final Duration ttl;

    public TokenFactory(JwtEncoder encoder, @Value("${demo.access-token-ttl}") Duration ttl) {
        this.encoder = encoder;
        this.ttl = ttl;
    }

    public Duration ttl() {
        return ttl;
    }

    public String createToken(String userName) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("token-factory-demo")
                .subject(userName)
                .issuedAt(now)
                .expiresAt(now.plus(ttl))
                .claim("clientId", userName)
                .claim("accounts", randomAccounts())
                .build();
        return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private List<Map<String, String>> randomAccounts() {
        return IntStream.range(0, ACCOUNTS_PER_TOKEN)
                .mapToObj(i -> Map.of("accountId", String.valueOf(random.nextInt(100_000, 1_000_000))))
                .toList();
    }
}
