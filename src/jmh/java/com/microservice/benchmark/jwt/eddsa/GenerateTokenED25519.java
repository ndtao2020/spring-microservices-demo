package com.microservice.benchmark.jwt.eddsa;

import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Payload;
import com.microservice.example.jwt.eddsa.EdDSAJwtBuilder;
import io.jsonwebtoken.Jwts;
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
import java.security.interfaces.EdECPrivateKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class GenerateTokenED25519 {

  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";

  private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
  private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
  private EdECPrivateKey privateKey;

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(GenerateTokenED25519.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }

  @Setup
  public void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
    generator.initialize(255, new SecureRandom());
    KeyPair keyPair = generator.generateKeyPair();
    // assign variables
    privateKey = (EdECPrivateKey) keyPair.getPrivate();
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
    jwe.setAlgorithmHeaderValue(AlgorithmIdentifiers.EDDSA);
    jwe.setKey(privateKey);

    return jwe.getCompactSerialization();
  }

  @Benchmark
  public String customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    var jwtBuilder = new EdDSAJwtBuilder(privateKey, com.microservice.example.jwt.Algorithm.ED25519);
    Payload payload = new Payload();
    payload.setJti(JWT_ID);
    payload.setIss(ISSUER);
    payload.setSub(SUBJECT);
    payload.setExp(expiresAt.getTime() / 1000);
    return jwtBuilder.compact(payload);
  }
}
