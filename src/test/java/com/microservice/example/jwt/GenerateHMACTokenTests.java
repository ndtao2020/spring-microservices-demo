package com.microservice.example.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.hmac.HMACJwtBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.hmac.HMACSigner;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import org.jboss.resteasy.jose.jws.JWSBuilder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("Generate a Token with HMAC - Test case")
class GenerateHMACTokenTests {

    private static final String JWT_ID = RandomUtils.generateId(20);
    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";

    private final String secret = RandomUtils.generatePassword(50);
    private final byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
    private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
    private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
    private final ZonedDateTime zoneExpiresAt = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60);

    @Test
    void customJWT() throws NoSuchAlgorithmException, InvalidKeyException {
        HMACJwtBuilder jwtBuilder = new HMACJwtBuilder(secretBytes, com.microservice.example.jwt.Algorithm.HS256);

        Map<String, Object> map = new HashMap<>();
        map.put(Claims.JWT_ID, JWT_ID);
        map.put(Claims.ISSUER, ISSUER);
        map.put(Claims.SUBJECT, SUBJECT);
        map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);

        String token = jwtBuilder.compact(map);

        assertNotNull(token);
    }

    @Test
    void customJWTwithDTO() throws NoSuchAlgorithmException, InvalidKeyException {
        HMACJwtBuilder jwtBuilder = new HMACJwtBuilder(secretBytes, com.microservice.example.jwt.Algorithm.HS256);

        Payload payload = new Payload();
        payload.setJti(JWT_ID);
        payload.setIss(ISSUER);
        payload.setSub(SUBJECT);
        payload.setExp(expiresAt.getTime() / 1000);

        String token = jwtBuilder.compact(payload);
        assertNotNull(token);
    }

    @Test
    void auth0JWT() {
        String token = JWT.create()
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .withExpiresAt(expiresAt)
                .sign(Algorithm.HMAC256(secretBytes));
        assertNotNull(token);
    }

    @Test
    void jsonWebToken() {
        String token = Jwts.builder()
                .id(JWT_ID)
                .issuer(ISSUER)
                .subject(SUBJECT)
                .expiration(expiresAt)
                .signWith(Keys.hmacShaKeyFor(secretBytes))
                .compact();

        assertNotNull(token);
    }

    @Test
    void nimbusJoseJWT() throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
                .jwtID(JWT_ID)
                .issuer(ISSUER)
                .subject(SUBJECT)
                .expirationTime(expiresAt)
                .build());
        signedJWT.sign(new MACSigner(secretBytes));

        String token = signedJWT.serialize();

        assertNotNull(token);
    }

    @Test
    void fusionAuth() {
        Signer signer = HMACSigner.newSHA256Signer(secretBytes);
        io.fusionauth.jwt.domain.JWT jwt = new io.fusionauth.jwt.domain.JWT()
                .setUniqueId(JWT_ID)
                .setIssuer(ISSUER)
                .setSubject(SUBJECT)
                .setExpiration(zoneExpiresAt);
        // Sign and encode the JWT to a JSON string representation
        String token = io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, signer);

        assertNotNull(token);
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
        jwe.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jwe.setKey(new HmacKey(secretBytes));

        String token = jwe.getCompactSerialization();

        assertNotNull(token);
    }

    @Test
    void vertxAuthJwt() {
        JWTOptions options = new JWTOptions();
        options.setIssuer(ISSUER);
        options.setAlgorithm("HS256");
        options.setSubject(SUBJECT);
        options.setExpiresInSeconds((int) (expiresAt.getTime() / 1000));

        JWTAuthOptions config = new JWTAuthOptions()
                .addPubSecKey(new PubSecKeyOptions().setAlgorithm("HS256").setBuffer(secret))
                .setJWTOptions(options);

        JWTAuth provider = JWTAuth.create(Vertx.vertx(), config);

        JsonObject jsonObject = new JsonObject();
        jsonObject.put(Claims.JWT_ID, JWT_ID);

        String token = provider.generateToken(jsonObject);

        assertNotNull(token);
    }

    @Test
    void jbossJoseJwt() {
        Map<String, Object> map = new HashMap<>();
        map.put(Claims.JWT_ID, JWT_ID);
        map.put(Claims.ISSUER, ISSUER);
        map.put(Claims.SUBJECT, SUBJECT);
        map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);

        String token = new JWSBuilder().jsonContent(map).hmac256(secretBytes);

        assertNotNull(token);
    }
}
