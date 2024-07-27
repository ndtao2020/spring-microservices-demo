package com.microservice.benchmark.jwt.rsa;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Claims;
import com.microservice.example.jwt.Payload;
import com.microservice.example.jwt.rsa.RSAJwtBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.rsa.RSASigner;
import io.jsonwebtoken.Jwts;
import org.jboss.resteasy.jose.jws.JWSBuilder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
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
public class GenerateTokenRS256 {

  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";

  private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
  private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
  private final ZonedDateTime zoneExpiresAt = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60);

  private RSAPrivateKey privateKey;

  @Setup
  public void setup() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048, new SecureRandom());
    KeyPair keyPair = generator.generateKeyPair();
    // assign variables
    privateKey = (RSAPrivateKey) keyPair.getPrivate();
  }

  @Benchmark
  public String customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    RSAJwtBuilder jwtBuilder = new RSAJwtBuilder(privateKey, com.microservice.example.jwt.Algorithm.RS256);

    Map<String, Object> map = new HashMap<>();
    map.put(Claims.JWT_ID, JWT_ID);
    map.put(Claims.ISSUER, ISSUER);
    map.put(Claims.SUBJECT, SUBJECT);
    map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);

    return jwtBuilder.compact(map);
  }

  @Benchmark
  public String customJWTwithDTO() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    RSAJwtBuilder jwtBuilder = new RSAJwtBuilder(privateKey, com.microservice.example.jwt.Algorithm.RS256);

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
        .sign(Algorithm.RSA256(privateKey));
  }

  @Benchmark
  public String jsonWebToken() {
    return Jwts.builder()
        .id(JWT_ID)
        .issuer(ISSUER)
        .subject(SUBJECT)
        .expiration(expiresAt)
        .signWith(privateKey)
        .compact();
  }

  @Benchmark
  public String nimbusJoseJWT() throws JOSEException {
    SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder()
        .jwtID(JWT_ID)
        .issuer(ISSUER)
        .subject(SUBJECT)
        .expirationTime(expiresAt)
        .build());
    signedJWT.sign(new RSASSASigner(privateKey));
    return signedJWT.serialize();
  }

  @Benchmark
  public String fusionAuth() {
    io.fusionauth.jwt.domain.JWT jwt = new io.fusionauth.jwt.domain.JWT()
        .setUniqueId(JWT_ID)
        .setIssuer(ISSUER)
        .setSubject(SUBJECT)
        .setExpiration(zoneExpiresAt);
    // Sign and encode the JWT to a JSON string representation
    return io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, RSASigner.newSHA256Signer(privateKey));
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
    jwe.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
    jwe.setKey(privateKey);

    return jwe.getCompactSerialization();
  }

  @Benchmark
  public String jbossJoseJwt() {
    Map<String, Object> map = new HashMap<>();
    map.put(Claims.JWT_ID, JWT_ID);
    map.put(Claims.ISSUER, ISSUER);
    map.put(Claims.SUBJECT, SUBJECT);
    map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);
    return new JWSBuilder().jsonContent(map).rsa256(privateKey);
  }

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(GenerateTokenRS256.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }
}
