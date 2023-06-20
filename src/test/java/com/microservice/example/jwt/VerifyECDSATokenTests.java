package com.microservice.example.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.ecdsa.ECDSAJwtParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.ec.ECVerifier;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Generate a Token with ECDSA - Test case")
class VerifyECDSATokenTests {

    private static final String JWT_ID = RandomUtils.generateId(20);
    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";

    static ECPublicKey publicKey;
    static ECPrivateKey privateKey;
    private final String generatedToken = JWT.create()
            .withJWTId(JWT_ID)
            .withIssuer(ISSUER)
            .withSubject(SUBJECT)
            .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
            .sign(Algorithm.ECDSA256(publicKey, privateKey));

    @BeforeAll
    static void initAll() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        // assign variables
        publicKey = (ECPublicKey) keyPair.getPublic();
        privateKey = (ECPrivateKey) keyPair.getPrivate();
    }

    @Test
    void customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        ECDSAJwtParser jwtParser = new ECDSAJwtParser(publicKey, com.microservice.example.jwt.Algorithm.ES256);
        Payload payload = jwtParser.verify(generatedToken);
        // Assert the subject of the JWT is as expected
        assertNotNull(payload);
        assertEquals(JWT_ID, payload.getJti());
        assertEquals(ISSUER, payload.getIss());
        assertEquals(SUBJECT, payload.getSub());
    }

    @Test
    void auth0JWT() {
        JWTVerifier verifier = JWT.require(Algorithm.ECDSA256(publicKey, privateKey))
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .build();
        assertNotNull(verifier.verify(generatedToken));
    }

    @Test
    void jsonWebToken() {
        JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .requireId(JWT_ID)
                .requireIssuer(ISSUER)
                .requireSubject(SUBJECT)
                .build();
        assertNotNull(jwtParser.parse(generatedToken));
    }

    @Test
    void nimbusJoseJWT() throws JOSEException, ParseException {
        SignedJWT signedJWT = SignedJWT.parse(generatedToken);
        assertTrue(signedJWT.verify(new ECDSAVerifier(publicKey)));
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        assertEquals(JWT_ID, jwtClaimsSet.getJWTID());
        assertEquals(ISSUER, jwtClaimsSet.getIssuer());
        assertEquals(SUBJECT, jwtClaimsSet.getSubject());
    }

    @Test
    void fusionAuth() {
        // Verify and decode the encoded string JWT to a rich object
        io.fusionauth.jwt.domain.JWT jwt = io.fusionauth.jwt.domain.JWT.getDecoder().decode(generatedToken, ECVerifier.newVerifier(publicKey));
        // Assert the subject of the JWT is as expected
        assertEquals(JWT_ID, jwt.uniqueId);
        assertEquals(ISSUER, jwt.issuer);
        assertEquals(SUBJECT, jwt.subject);
    }

    @Test
    void bitbucketBC() throws InvalidJwtException, MalformedClaimException {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(ISSUER) // whom the JWT needs to have been issued by
                .setExpectedSubject(SUBJECT)
                .setVerificationKey(publicKey)
                .build();
        JwtClaims jwtClaims = jwtConsumer.processToClaims(generatedToken);
        // Assert the subject of the JWT is as expected
        assertNotNull(jwtClaims);
        assertEquals(JWT_ID, jwtClaims.getJwtId());
    }
}
