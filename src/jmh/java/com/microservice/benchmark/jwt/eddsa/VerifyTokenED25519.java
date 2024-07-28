package com.microservice.benchmark.jwt.eddsa;

import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Payload;
import com.microservice.example.jwt.eddsa.EdDSAJwtParser;
import io.jsonwebtoken.Jwts;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.EdECPublicKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class VerifyTokenED25519 {

  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";
  private EdECPublicKey publicKey;
  private String generatedToken;

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(VerifyTokenED25519.class.getSimpleName())
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
    publicKey = (EdECPublicKey) keyPair.getPublic();
    // generate a token
    generatedToken = Jwts.builder()
        .id(JWT_ID)
        .issuer(ISSUER)
        .subject(SUBJECT)
        .expiration(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
        .signWith(keyPair.getPrivate())
        .compact();
  }

  @Benchmark
  public Payload customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
    var jwtParser = new EdDSAJwtParser(publicKey, Algorithm.ED25519);
    return jwtParser.verify(generatedToken);
  }

  @Benchmark
  public JwtClaims bitbucketBC() throws InvalidJwtException {
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setRequireExpirationTime() // the JWT must have an expiration time
        .setRequireSubject() // the JWT must have a subject claim
        .setExpectedIssuer(ISSUER) // whom the JWT needs to have been issued by
        .setExpectedSubject(SUBJECT)
        .setVerificationKey(publicKey)
        .build();
    return jwtConsumer.processToClaims(generatedToken);
  }

  @Benchmark
  public Object jsonWebToken() {
    return Jwts.parser()
        .verifyWith(publicKey)
        .requireId(JWT_ID)
        .requireIssuer(ISSUER)
        .requireSubject(SUBJECT)
        .build()
        .parse(generatedToken);
  }
}
