package com.example.tokenfactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Creates a signed JWT for a given user name, optionally wrapped in a compact JWE.
 * The token carries a {@code clientId} claim (the user name) and two accounts
 * with a random 6-digit accountId each. When {@code demo.encrypt-tokens} is on, the
 * signed JWT is encrypted into a nested JWT so the client receives an opaque token.
 */
@Component
public class TokenFactory {

    private static final int ACCOUNTS_PER_TOKEN = 2;

    private final JwtEncoder encoder;
    private final SecretKey encryptionKey;
    private final boolean encrypt;
    private final SecureRandom random = new SecureRandom();
    private final Duration ttl;

    public TokenFactory(JwtEncoder encoder, SecretKey encryptionKey,
                        @Value("${demo.encrypt-tokens}") boolean encrypt,
                        @Value("${demo.access-token-ttl}") Duration ttl) {
        this.encoder = encoder;
        this.encryptionKey = encryptionKey;
        this.encrypt = encrypt;
        this.ttl = ttl;
    }

    public Duration ttl() {
        return ttl;
    }

    /**
     * Prints one sample encrypted token at startup so it is plainly visible that the
     * access token is now an opaque JWE. Runs only when encryption is enabled.
     */
    @PostConstruct
    void printSampleEncryptedToken() {
        if (!encrypt) {
            return;
        }
        System.out.println("\n--- Encrypted access token (a 'dir' JWE, opaque to the client) ---");
        System.out.println(createToken("alice"));
        System.out.println("--- The five dot-separated parts above are the encrypted nested JWT ---\n");
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
        String signed = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return encrypt ? encryptToken(signed) : signed;
    }

    /**
     * Wraps the signed JWT in a "dir" + A128GCM JWE (a nested JWT). Direct symmetric
     * encryption puts no wrapped key in the token, so it grows only by a small header,
     * a 12-byte IV and a 16-byte tag on top of the base64 of the signed JWT.
     */
    private String encryptToken(String signedToken) {
        try {
            JWEObject jwe = new JWEObject(
                    new JWEHeader.Builder(JwtConfig.KEY_ALGORITHM, JwtConfig.CONTENT_ENCRYPTION)
                            .contentType("JWT") // marks the payload as a nested JWT
                            .build(),
                    new Payload(signedToken));
            jwe.encrypt(new DirectEncrypter(encryptionKey));
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
