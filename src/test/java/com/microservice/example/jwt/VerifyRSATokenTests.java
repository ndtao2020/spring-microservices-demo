package com.microservice.example.jwt;

import com.alibaba.fastjson2.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.rsa.RSAJwtParser;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.fusionauth.jwt.rsa.RSAVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("Generate a Token with RSA - Test case")
class VerifyRSATokenTests {

    private static final String JWT_ID = RandomUtils.generateId(20);
    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";

    static RSAPublicKey publicKey;
    static RSAPrivateKey privateKey;
    private final String generatedToken = JWT.create()
            .withJWTId(JWT_ID)
            .withIssuer(ISSUER)
            .withSubject(SUBJECT)
            .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
            .sign(Algorithm.RSA256(publicKey, privateKey));

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
        RSAJwtParser jwtParser = new RSAJwtParser(publicKey, com.microservice.example.jwt.Algorithm.RS256);
        JSONObject jsonObject = jwtParser.verify(generatedToken);
        // Assert the subject of the JWT is as expected
        assertNotNull(jsonObject);
        assertEquals(JWT_ID, jsonObject.getString(Claims.JWT_ID));
        assertEquals(ISSUER, jsonObject.getString(Claims.ISSUER));
        assertEquals(SUBJECT, jsonObject.getString(Claims.SUBJECT));
    }

    @Test
    void auth0JWT() {
        JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKey, privateKey))
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .build();
        assertNotNull(verifier.verify(generatedToken));
    }

    @Test
    void fusionAuth() {
        // Verify and decode the encoded string JWT to a rich object
        io.fusionauth.jwt.domain.JWT jwt = io.fusionauth.jwt.domain.JWT.getDecoder().decode(generatedToken, RSAVerifier.newVerifier(publicKey));
        // Assert the subject of the JWT is as expected
        assertEquals(JWT_ID, jwt.uniqueId);
        assertEquals(ISSUER, jwt.issuer);
        assertEquals(SUBJECT, jwt.subject);
    }
}
