package com.microservice.example.jwt;

import com.alibaba.fastjson2.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.hmac.HMACJwtParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Generate a Token with HMAC - Test case")
class VerifyHMACTokenTests {

    private static final String JWT_ID = RandomUtils.generateId(20);
    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";

    private final String secret = RandomUtils.generatePassword(50);
    private final byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
    private final String generatedToken = JWT.create()
            .withJWTId(JWT_ID)
            .withIssuer(ISSUER)
            .withSubject(SUBJECT)
            .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
            .sign(Algorithm.HMAC256(secretBytes));

    @Test
    void customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        HMACJwtParser jwtParser = new HMACJwtParser(secretBytes, com.microservice.example.jwt.Algorithm.HS256);
        JSONObject jsonObject = jwtParser.verify(generatedToken);
        // Assert the subject of the JWT is as expected
        assertNotNull(jsonObject);
        assertEquals(JWT_ID, jsonObject.getString(Claims.JWT_ID));
        assertEquals(ISSUER, jsonObject.getString(Claims.ISSUER));
        assertEquals(SUBJECT, jsonObject.getString(Claims.SUBJECT));
    }

    @Test
    void auth0JWT() {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secretBytes))
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .build();

        assertNotNull(verifier.verify(generatedToken));
    }

    @Test
    void jsonWebToken() {
        JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secretBytes))
                .requireId(JWT_ID)
                .requireIssuer(ISSUER)
                .requireSubject(SUBJECT)
                .build();
        assertNotNull(jwtParser.parse(generatedToken));
    }

    @Test
    void nimbusJoseJWT() throws JOSEException, ParseException {
        SignedJWT signedJWT = SignedJWT.parse(generatedToken);
        JWSVerifier verifier = new MACVerifier(secretBytes);
        assertTrue(signedJWT.verify(verifier));

        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();

        assertEquals(JWT_ID, jwtClaimsSet.getJWTID());
        assertEquals(ISSUER, jwtClaimsSet.getIssuer());
        assertEquals(SUBJECT, jwtClaimsSet.getSubject());
    }

    @Test
    void fusionAuth() {
        // Verify and decode the encoded string JWT to a rich object
        io.fusionauth.jwt.domain.JWT jwt = io.fusionauth.jwt.domain.JWT.getDecoder().decode(generatedToken, HMACVerifier.newVerifier(secretBytes));
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
                .setVerificationKey(new HmacKey(secretBytes))
                .build();

        JwtClaims jwtClaims = jwtConsumer.processToClaims(generatedToken);
        // Assert the subject of the JWT is as expected
        assertNotNull(jwtClaims);
        assertEquals(JWT_ID, jwtClaims.getJwtId());
    }

    @Test
    void vertxAuthJwt() {
        JWTAuthOptions config = new JWTAuthOptions()
                .addPubSecKey(new PubSecKeyOptions().setAlgorithm("HS256").setBuffer(secret));

        JWTAuth provider = JWTAuth.create(Vertx.vertx(), config);

        provider.authenticate(new TokenCredentials(generatedToken), result -> {
            assert result.succeeded();
            User user = result.result();
            JsonObject jsonObject = user.principal();
            // Assert the subject of the JWT is as expected
            assertNotNull(user);
            assertNotNull(jsonObject);
            assertEquals(JWT_ID, jsonObject.getString(Claims.JWT_ID));
            assertEquals(ISSUER, jsonObject.getString(Claims.ISSUER));
            assertEquals(SUBJECT, jsonObject.getString(Claims.SUBJECT));
        });
    }
}
