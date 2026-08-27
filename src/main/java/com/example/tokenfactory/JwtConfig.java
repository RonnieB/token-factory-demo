package com.example.tokenfactory;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * One in-memory RSA key pair signs and verifies tokens. When {@code demo.encrypt-tokens}
 * is on, an in-memory AES key additionally encrypts the signed JWT into a nested JWT.
 * A real deployment would load these from a keystore or fetch a JWKS instead.
 *
 * <p>The encryption uses direct symmetric encryption ("dir") rather than RSA key wrapping,
 * so the token carries no encrypted content-encryption key — the only size overhead is a
 * small JWE header, a 12-byte IV and a 16-byte auth tag. RSA-OAEP would have added roughly
 * 340 characters for the wrapped key alone, which matters because JWT size is limited.
 */
@Configuration
public class JwtConfig {

    static final JWEAlgorithm KEY_ALGORITHM = JWEAlgorithm.DIR;
    static final EncryptionMethod CONTENT_ENCRYPTION = EncryptionMethod.A128GCM;

    @Bean
    KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /** 128-bit AES key shared by the encoder and decoder for the optional "dir" JWE layer. */
    @Bean
    SecretKey tokenEncryptionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }

    @Bean
    JwtEncoder jwtEncoder(KeyPair keyPair) {
        RSAKey key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("signing-key")
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }

    /**
     * Verifies a plain signed JWT, or — when encryption is on — decrypts the JWE with the
     * shared AES key first and then verifies the signature of the JWS it contained.
     */
    @Bean
    JwtDecoder jwtDecoder(KeyPair keyPair, SecretKey encryptionKey,
                          @Value("${demo.encrypt-tokens}") boolean encrypt) {
        if (!encrypt) {
            return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
        }

        RSAKey signingKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyID("signing-key") // must match the kid the encoder stamps on the JWS
                .build();
        OctetSequenceKey octKey = new OctetSequenceKey.Builder(encryptionKey).build();

        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWEKeySelector(new JWEDecryptionKeySelector<>(
                KEY_ALGORITHM, CONTENT_ENCRYPTION, new ImmutableJWKSet<>(new JWKSet(octKey))));
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256, new ImmutableJWKSet<>(new JWKSet(signingKey))));
        processor.setJWEDecrypterFactory(new DefaultJWEDecrypterFactory());
        return new NimbusJwtDecoder(processor);
    }
}
