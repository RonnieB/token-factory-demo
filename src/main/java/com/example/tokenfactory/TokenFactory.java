package com.example.tokenfactory;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Creates a nested JWT for a given user name: a signed JWT (carrying a {@code clientId} claim
 * and two accounts with random 6-digit ids) that is then encrypted so its contents are hidden.
 */
@Component
public class TokenFactory {

    /** The signed token before encryption and the encrypted token handed to the client. */
    public record Nested(String signed, String encrypted) {
    }

    private static final int ACCOUNTS_PER_TOKEN = 2;

    private final JwtEncoder encoder;
    private final RSAPublicKey encryptionKey;
    private final SecureRandom random = new SecureRandom();
    private final Duration ttl;

    public TokenFactory(JwtEncoder encoder,
                        @Qualifier("encryption") KeyPair encryptionKeyPair,
                        @Value("${demo.access-token-ttl}") Duration ttl) {
        this.encoder = encoder;
        this.encryptionKey = (RSAPublicKey) encryptionKeyPair.getPublic();
        this.ttl = ttl;
    }

    public Duration ttl() {
        return ttl;
    }

    /** Convenience for callers that only need the token to hand out: the encrypted form. */
    public String createToken(String userName) {
        return createNestedToken(userName).encrypted();
    }

    /** Returns both the signed and the encrypted form so the two stages can be compared. */
    public Nested createNestedToken(String userName) {
        String signed = sign(userName);
        return new Nested(signed, encrypt(signed));
    }

    private String sign(String userName) {
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

    private String encrypt(String signedJwt) {
        try {
            JWEObject jwe = new JWEObject(
                    new JWEHeader.Builder(JwtConfig.KEY_ALGORITHM, JwtConfig.CONTENT_ENCRYPTION)
                            .contentType("JWT") // marks the payload as a nested JWT
                            .build(),
                    new Payload(signedJwt));
            jwe.encrypt(new RSAEncrypter(encryptionKey));
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to encrypt token", e);
        }
    }

    private List<Map<String, String>> randomAccounts() {
        return IntStream.range(0, ACCOUNTS_PER_TOKEN)
                .mapToObj(i -> Map.of("accountId", String.valueOf(random.nextInt(100_000, 1_000_000))))
                .toList();
    }
}
