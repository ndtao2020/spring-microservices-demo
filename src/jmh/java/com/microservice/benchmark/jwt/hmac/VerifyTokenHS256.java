package com.microservice.benchmark.jwt.hmac;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Payload;
import com.microservice.example.jwt.hmac.HMACJwtParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.hmac.HMACVerifier;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.jboss.resteasy.jose.jws.JWSInput;
import org.jboss.resteasy.jose.jws.JWSInputException;
import org.jboss.resteasy.jose.jws.crypto.HMACProvider;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class VerifyTokenHS256 {

  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";

  private final String secret = RandomUtils.generatePassword(50);
  private final byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);

  private String generatedToken;

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(VerifyTokenHS256.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }

  @Setup
  public void setup() {
    generatedToken = JWT.create()
        .withJWTId(JWT_ID)
        .withIssuer(ISSUER)
        .withSubject(SUBJECT)
        .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
        .sign(Algorithm.HMAC256(secretBytes));
  }

  @Benchmark
  public Payload customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    HMACJwtParser jwtParser = new HMACJwtParser(secretBytes, com.microservice.example.jwt.Algorithm.HS256);
    return jwtParser.verify(generatedToken);
  }

  @Benchmark
  public DecodedJWT auth0JWT() {
    final JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(secretBytes))
        .withJWTId(JWT_ID)
        .withIssuer(ISSUER)
        .withSubject(SUBJECT)
        .build();
    return jwtVerifier.verify(generatedToken);
  }

  @Benchmark
  public JWTClaimsSet nimbusJoseJWT() throws JOSEException, ParseException, SignatureException {
    SignedJWT signedJWT = SignedJWT.parse(generatedToken);
    JWSVerifier verifier = new MACVerifier(secretBytes);
    if (!signedJWT.verify(verifier)) {
      throw new SignatureException("Token is invalid !");
    }
    return signedJWT.getJWTClaimsSet();
  }

  @Benchmark
  public io.fusionauth.jwt.domain.JWT fusionAuth() {
    // Sign and encode the JWT to a JSON string representation
    return io.fusionauth.jwt.domain.JWT.getDecoder().decode(generatedToken, HMACVerifier.newVerifier(secretBytes));
  }

  @Benchmark
  public JwtClaims bitbucketBC() throws InvalidJwtException {
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setRequireExpirationTime() // the JWT must have an expiration time
        .setRequireSubject() // the JWT must have a subject claim
        .setExpectedIssuer(ISSUER) // whom the JWT needs to have been issued by
        .setExpectedSubject(SUBJECT)
        .setVerificationKey(new HmacKey(secretBytes))
        .build();
    return jwtConsumer.processToClaims(generatedToken);
  }

  @Benchmark
  public Payload jbossJoseJwt() throws JWSInputException, SignatureException {
    JWSInput input = new JWSInput(generatedToken, ResteasyProviderFactory.getInstance());
    if (!HMACProvider.verify(input, secretBytes)) {
      throw new SignatureException("Token is invalid !");
    }
    return input.readJsonContent(Payload.class);
  }

  @Benchmark
  public Object jsonWebToken() {
    return Jwts.parser()
        .verifyWith(Keys.hmacShaKeyFor(secretBytes))
        .requireId(JWT_ID)
        .requireIssuer(ISSUER)
        .requireSubject(SUBJECT)
        .build()
        .parse(generatedToken);
  }
}
