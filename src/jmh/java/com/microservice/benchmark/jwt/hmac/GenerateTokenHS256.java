package com.microservice.benchmark.jwt.hmac;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class GenerateTokenHS256 {

    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";
    private final byte[] secretBytes = "IJTD@MFc7yUa5MhvcP03n#JPyCPzZtQcGEpz".getBytes(StandardCharsets.UTF_8);
    private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
    private final ZonedDateTime zoneExpiresAt = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60);

    @Benchmark
    public String auth0JWT() {
        return JWT.create()
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .withExpiresAt(expiresAt)
                .sign(Algorithm.HMAC256(secretBytes));
    }

    @Benchmark
    public String jsonWebToken() {
        return Jwts.builder()
                .setIssuer(ISSUER)
                .setSubject(SUBJECT)
                .setExpiration(expiresAt)
                .signWith(Keys.hmacShaKeyFor(secretBytes), SignatureAlgorithm.HS256)
                .compact();
    }

    @Benchmark
    public String nimbusJoseJWT() throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
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
                .setIssuer(ISSUER)
                .setSubject(SUBJECT)
                .setExpiration(zoneExpiresAt);
        // Sign and encode the JWT to a JSON string representation
        return io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, signer);
    }
}
