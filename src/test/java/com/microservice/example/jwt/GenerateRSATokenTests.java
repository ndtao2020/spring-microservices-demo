package com.microservice.example.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.rsa.RSAJwtBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.rsa.RSASigner;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.jboss.resteasy.jose.jws.JWSBuilder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
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

    static RSAPublicKey publicKey;
    static RSAPrivateKey privateKey;

    private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
    private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
    private final ZonedDateTime zoneExpiresAt = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60);

    private final JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKey, privateKey))
            .withJWTId(JWT_ID)
            .withIssuer(ISSUER)
            .withSubject(SUBJECT)
            .build();

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
        assertNotNull(verifier.verify(token));
    }

    @Test
    void customJWTwithDTO() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        RSAJwtBuilder jwtBuilder = new RSAJwtBuilder(privateKey, com.microservice.example.jwt.Algorithm.RS256);

        Payload payload = new Payload();
        payload.setJti(JWT_ID);
        payload.setIss(ISSUER);
        payload.setSub(SUBJECT);
        payload.setExp(expiresAt.getTime() / 1000);

        String token = jwtBuilder.compact(payload);

        assertNotNull(token);
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
        assertNotNull(verifier.verify(token));
    }

    @Test
    void jsonWebToken() {
        String token = Jwts.builder()
                .setId(JWT_ID)
                .setIssuer(ISSUER)
                .setSubject(SUBJECT)
                .setExpiration(expiresAt)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        assertNotNull(token);
        assertNotNull(verifier.verify(token));
    }

    @Test
    void nimbusJoseJWT() throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder()
                .jwtID(JWT_ID)
                .issuer(ISSUER)
                .subject(SUBJECT)
                .expirationTime(expiresAt)
                .build());
        signedJWT.sign(new RSASSASigner(privateKey));

        String token = signedJWT.serialize();

        assertNotNull(token);
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
        assertNotNull(verifier.verify(token));
    }

    @Test
    void bitbucketBC() throws JoseException {
        // Create the Claims, which will be the content of the JWT
        JwtClaims claims = new JwtClaims();
        claims.setJwtId(JWT_ID);
        claims.setIssuer(ISSUER);  // who creates the token and signs it
        claims.setSubject(SUBJECT); // the subject/principal is whom the token is about
        claims.setExpirationTime(numericDate);
        // A JWT is a JWS and/or a JWE with JSON claims as the payload.
        JsonWebSignature jwe = new JsonWebSignature();
        jwe.setPayload(claims.toJson());
        jwe.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jwe.setKey(privateKey);

        String token = jwe.getCompactSerialization();

        assertNotNull(token);
        assertNotNull(verifier.verify(token));
    }

    @Test
    void jbossJoseJwt() {
        Map<String, Object> map = new HashMap<>();
        map.put(Claims.JWT_ID, JWT_ID);
        map.put(Claims.ISSUER, ISSUER);
        map.put(Claims.SUBJECT, SUBJECT);
        map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);

        String token = new JWSBuilder().jsonContent(map).rsa256(privateKey);

        assertNotNull(token);
        assertNotNull(verifier.verify(token));
    }
}
