package com.microservice.benchmark.jwt.rsa;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Payload;
import com.microservice.example.jwt.rsa.RSAJwtParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.rsa.RSAVerifier;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.jboss.resteasy.jose.jws.JWSInput;
import org.jboss.resteasy.jose.jws.JWSInputException;
import org.jboss.resteasy.jose.jws.crypto.RSAProvider;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.openjdk.jmh.annotations.*;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class VerifyTokenRS256 {

  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";

  private RSAPublicKey publicKey;
  private String generatedToken;

  @Setup
  public void setup() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048, new SecureRandom());
    KeyPair keyPair = generator.generateKeyPair();
    // assign variables
    publicKey = (RSAPublicKey) keyPair.getPublic();
    // generate a token
    generatedToken = JWT.create()
        .withJWTId(JWT_ID)
        .withIssuer(ISSUER)
        .withSubject(SUBJECT)
        .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
        .sign(Algorithm.RSA256(publicKey, (RSAPrivateKey) keyPair.getPrivate()));
  }

  @Benchmark
  public Payload customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    RSAJwtParser jwtParser = new RSAJwtParser(publicKey, com.microservice.example.jwt.Algorithm.RS256);
    return jwtParser.verify(generatedToken);
  }

  @Benchmark
  public Payload customJWTIndexOf() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    RSAJwtParser jwtParser = new RSAJwtParser(publicKey, com.microservice.example.jwt.Algorithm.RS256);
    return jwtParser.verifyIndexOf(generatedToken);
  }

  @Benchmark
  public JWTVerifier auth0JWT() {
    return JWT.require(Algorithm.RSA256(publicKey))
        .withJWTId(JWT_ID)
        .withIssuer(ISSUER)
        .withSubject(SUBJECT)
        .build();
  }

  @Benchmark
  public Jwt jsonWebToken() {
    return Jwts.parser()
        .verifyWith(publicKey)
        .requireId(JWT_ID)
        .requireIssuer(ISSUER)
        .requireSubject(SUBJECT)
        .build()
        .parse(generatedToken);
  }

  @Benchmark
  public JWTClaimsSet nimbusJoseJWT() throws JOSEException, ParseException, SignatureException {
    SignedJWT signedJWT = SignedJWT.parse(generatedToken);
    if (!signedJWT.verify(new RSASSAVerifier(publicKey))) {
      throw new SignatureException("Token is invalid !");
    }
    return signedJWT.getJWTClaimsSet();
  }

  @Benchmark
  public io.fusionauth.jwt.domain.JWT fusionAuth() {
    // Sign and encode the JWT to a JSON string representation
    return io.fusionauth.jwt.domain.JWT.getDecoder().decode(generatedToken, RSAVerifier.newVerifier(publicKey));
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
  public Payload jbossJoseJwt() throws JWSInputException, SignatureException {
    JWSInput input = new JWSInput(generatedToken, ResteasyProviderFactory.getInstance());
    if (!RSAProvider.verify(input, publicKey)) {
      throw new SignatureException("Token is invalid !");
    }
    return input.readJsonContent(Payload.class);
  }
}
