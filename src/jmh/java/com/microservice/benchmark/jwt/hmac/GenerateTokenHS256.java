package com.microservice.benchmark.jwt.hmac;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Claims;
import com.microservice.example.jwt.Payload;
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
import io.jsonwebtoken.security.Keys;
import org.jboss.resteasy.jose.jws.JWSBuilder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class GenerateTokenHS256 {

  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";

  private final String secret = RandomUtils.generatePassword(50);
  private final byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
  private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
  private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
  private final ZonedDateTime zoneExpiresAt = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60);

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(GenerateTokenHS256.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }

  @Benchmark
  public String customJWTwithDTO() throws NoSuchAlgorithmException, InvalidKeyException {
    HMACJwtBuilder jwtBuilder = new HMACJwtBuilder(secretBytes, com.microservice.example.jwt.Algorithm.HS256);

    Payload payload = new Payload();
    payload.setJti(JWT_ID);
    payload.setIss(ISSUER);
    payload.setSub(SUBJECT);
    payload.setExp(expiresAt.getTime() / 1000);

    return jwtBuilder.compact(payload);
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
        .id(JWT_ID)
        .issuer(ISSUER)
        .subject(SUBJECT)
        .expiration(expiresAt)
        .signWith(Keys.hmacShaKeyFor(secretBytes))
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

  @Benchmark
  public String jbossJoseJwt() {
    Map<String, Object> map = new HashMap<>();
    map.put(Claims.JWT_ID, JWT_ID);
    map.put(Claims.ISSUER, ISSUER);
    map.put(Claims.SUBJECT, SUBJECT);
    map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);
    return new JWSBuilder().jsonContent(map).hmac256(secretBytes);
  }
}
