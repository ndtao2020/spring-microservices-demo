package com.microservice.example.jwt;

import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.eddsa.EdDSAJwtParser;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("Generate a Token with EdDSA - Test case")
class VerifyEdDSATokenTests {

  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";

  static EdECPublicKey publicKey;
  static EdECPrivateKey privateKey;
  private final String generatedToken = Jwts.builder()
      .id(JWT_ID)
      .issuer(ISSUER)
      .subject(SUBJECT)
      .expiration(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
      .signWith(privateKey)
      .compact();

  @BeforeAll
  static void initAll() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
    KeyPair keyPair = generator.generateKeyPair();
    // assign variables
    publicKey = (EdECPublicKey) keyPair.getPublic();
    privateKey = (EdECPrivateKey) keyPair.getPrivate();
  }

  @Test
  void customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
    var jwtParser = new EdDSAJwtParser(publicKey, Algorithm.ED25519);
    Payload payload = jwtParser.verify(generatedToken);
    // Assert the subject of the JWT is as expected
    assertNotNull(payload);
    assertEquals(JWT_ID, payload.getJti());
    assertEquals(ISSUER, payload.getIss());
    assertEquals(SUBJECT, payload.getSub());
  }

  @Test
  void jsonWebToken() {
    JwtParser jwtParser = Jwts.parser()
        .verifyWith(publicKey)
        .requireId(JWT_ID)
        .requireIssuer(ISSUER)
        .requireSubject(SUBJECT)
        .build();
    assertNotNull(jwtParser.parse(generatedToken));
  }

  @Test
  void bitbucketBC() throws InvalidJwtException, MalformedClaimException {
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setRequireExpirationTime() // the JWT must have an expiration time
        .setRequireSubject() // the JWT must have a subject claim
        .setExpectedIssuer(ISSUER) // whom the JWT needs to have been issued by
        .setExpectedSubject(SUBJECT)
        .setVerificationKey(publicKey)
        .build();
    JwtClaims jwtClaims = jwtConsumer.processToClaims(generatedToken);
    // Assert the subject of the JWT is as expected
    assertNotNull(jwtClaims);
    assertEquals(JWT_ID, jwtClaims.getJwtId());
  }
}
