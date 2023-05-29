package com.microservice.benchmark.jwt.hmac;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.microservice.example.jwt.Claims;
import com.microservice.example.jwt.hmac.JwtBuilder;
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
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class GenerateTokenHS256 {

    private static final String JWT_ID = UUID.randomUUID().toString();
    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";

    private final byte[] secretBytes = "IJTD@MFc7yUa5MhvcP03n#JPyCPzZtQcGEpz".getBytes(StandardCharsets.UTF_8);
    private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
    private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
    private final ZonedDateTime zoneExpiresAt = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60);

    @Benchmark
    public String customJWT() throws NoSuchAlgorithmException, InvalidKeyException, JsonProcessingException {
        JwtBuilder jwtBuilder = new JwtBuilder(secretBytes, com.microservice.example.jwt.Algorithm.HS256);

        Map<String, Object> map = new HashMap<>();
        map.put(Claims.JWT_ID, JWT_ID);
        map.put(Claims.ISSUER, ISSUER);
        map.put(Claims.SUBJECT, SUBJECT);
        map.put(Claims.EXPIRES_AT, expiresAt);

        return jwtBuilder.compact(map);
    }

    @Benchmark
    public String auth0JWT() {
        return JWT.create()
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .withExpiresAt(expiresAt)
                .sign(Algorithm.HMAC256(secretBytes));
    }

    @Benchmark
    public String jsonWebToken() {
        return Jwts.builder()
                .setId(JWT_ID)
                .setIssuer(ISSUER)
                .setSubject(SUBJECT)
                .setExpiration(expiresAt)
                .signWith(Keys.hmacShaKeyFor(secretBytes), SignatureAlgorithm.HS256)
                .compact();
    }

    @Benchmark
    public String nimbusJoseJWT() throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
                .jwtID(JWT_ID)
                .issuer(ISSUER)
                .subject(SUBJECT)
                .expirationTime(expiresAt)
                .build());
        signedJWT.sign(new MACSigner(secretBytes));
        return signedJWT.serialize();
    }

    @Benchmark
    public String fusionAuth() {
        Signer signer = HMACSigner.newSHA256Signer(secretBytes);
        io.fusionauth.jwt.domain.JWT jwt = new io.fusionauth.jwt.domain.JWT()
                .setUniqueId(JWT_ID)
                .setIssuer(ISSUER)
                .setSubject(SUBJECT)
                .setExpiration(zoneExpiresAt);
        // Sign and encode the JWT to a JSON string representation
        return io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, signer);
    }

    @Benchmark
    public String bitbucketBC() throws JoseException {
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
        return jwe.getCompactSerialization();
    }
}
