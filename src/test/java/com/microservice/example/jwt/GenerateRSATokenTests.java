package com.microservice.example.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.rsa.RSAJwtBuilder;
import io.fusionauth.jwt.rsa.RSASigner;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("Generate a Token with RSA - Test case")
class GenerateRSATokenTests {

    private static final String JWT_ID = RandomUtils.generateId(20);
    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";

    private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
    private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
    private final ZonedDateTime zoneExpiresAt = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60);

    static RSAPublicKey publicKey;
    static RSAPrivateKey privateKey;

    @BeforeAll
    static void initAll() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        // assign variables
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
    }

    @Test
    void customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        RSAJwtBuilder jwtBuilder = new RSAJwtBuilder(privateKey, com.microservice.example.jwt.Algorithm.RS256);

        Map<String, Object> map = new HashMap<>();
        map.put(Claims.JWT_ID, JWT_ID);
        map.put(Claims.ISSUER, ISSUER);
        map.put(Claims.SUBJECT, SUBJECT);
        map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);

        String token = jwtBuilder.compact(map);

        assertNotNull(token);

        JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKey, privateKey))
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .build();

        assertNotNull(verifier.verify(token));
    }

    @Test
    void auth0JWT() {
        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);

        String token = JWT.create()
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .withExpiresAt(expiresAt)
                .sign(algorithm);

        assertNotNull(token);

        JWTVerifier verifier = JWT.require(algorithm)
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .build();

        assertNotNull(verifier.verify(token));
    }

    @Test
    void fusionAuth() {
        io.fusionauth.jwt.domain.JWT jwt = new io.fusionauth.jwt.domain.JWT()
                .setUniqueId(JWT_ID)
                .setIssuer(ISSUER)
                .setSubject(SUBJECT)
                .setExpiration(zoneExpiresAt);
        // Sign and encode the JWT to a JSON string representation
        String token = io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, RSASigner.newSHA256Signer(privateKey));

        assertNotNull(token);

        JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKey, privateKey))
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .build();

        assertNotNull(verifier.verify(token));
    }
}
