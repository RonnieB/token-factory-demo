package com.example.tokenfactory;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Two in-memory RSA key pairs:
 *   - the signing pair proves who issued the token (private key signs, public key verifies);
 *   - the encryption pair keeps the contents secret (public key encrypts, private key decrypts).
 * Splitting them mirrors real deployments, where the sender signs and the recipient decrypts.
 * A real system would load these from a keystore instead of generating them at startup.
 */
@Configuration
public class JwtConfig {

    static final JWEAlgorithm KEY_ALGORITHM = JWEAlgorithm.RSA_OAEP_256;
    static final EncryptionMethod CONTENT_ENCRYPTION = EncryptionMethod.A256GCM;

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    @Bean
    @Qualifier("signing")
    KeyPair signingKeyPair() throws Exception {
        return rsa();
    }

    @Bean
    @Qualifier("encryption")
    KeyPair encryptionKeyPair() throws Exception {
        return rsa();
    }

    @Bean
    JwtEncoder jwtEncoder(@Qualifier("signing") KeyPair signing) {
        RSAKey key = new RSAKey.Builder((RSAPublicKey) signing.getPublic())
                .privateKey((RSAPrivateKey) signing.getPrivate())
                .keyID("signing-key")
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }

    /**
     * Decodes a nested JWT: the processor decrypts the JWE with the encryption private key,
     * then verifies the signature of the JWS it contained with the signing public key.
     */
    @Bean
    JwtDecoder jwtDecoder(@Qualifier("signing") KeyPair signing,
                          @Qualifier("encryption") KeyPair encryption) {
        RSAKey encryptionKey = new RSAKey.Builder((RSAPublicKey) encryption.getPublic())
                .privateKey((RSAPrivateKey) encryption.getPrivate())
                .build();
        RSAKey signingKey = new RSAKey.Builder((RSAPublicKey) signing.getPublic())
                .keyID("signing-key") // must match the kid the encoder stamps on the JWS
                .build();

        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWEKeySelector(new JWEDecryptionKeySelector<>(
                KEY_ALGORITHM, CONTENT_ENCRYPTION, new ImmutableJWKSet<>(new JWKSet(encryptionKey))));
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
                JWSAlgorithm.RS256, new ImmutableJWKSet<>(new JWKSet(signingKey))));
        processor.setJWEDecrypterFactory(new DefaultJWEDecrypterFactory());
        return new NimbusJwtDecoder(processor);
    }
}
