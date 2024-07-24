package com.microservice.example.jwt;

import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.eddsa.EdDSAJwtBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

// https://curity.io/resources/learn/sign-tokens-with-eddsa/?tab=Decoded-JWT
@DisplayName("Generate a Token with EdDSA - Test case")
class GenerateEdDSATokenTests {

  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";

  static EdECPublicKey publicKey;
  static EdECPrivateKey privateKey;

  private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
  private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
  private final JwtParser jwtParser = Jwts.parser()
      .verifyWith(publicKey)
      .requireId(JWT_ID)
      .requireIssuer(ISSUER)
      .requireSubject(SUBJECT)
      .build();

  @BeforeAll
  static void initAll() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
    KeyPair keyPair = generator.generateKeyPair();
    // assign variables
    publicKey = (EdECPublicKey) keyPair.getPublic();
    privateKey = (EdECPrivateKey) keyPair.getPrivate();
  }

  @Test
  void customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    EdDSAJwtBuilder jwtBuilder = new EdDSAJwtBuilder(privateKey, Algorithm.ED25519);

    Map<String, Object> map = new HashMap<>();
    map.put(Claims.JWT_ID, JWT_ID);
    map.put(Claims.ISSUER, ISSUER);
    map.put(Claims.SUBJECT, SUBJECT);
    map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);

    String token = jwtBuilder.compact(map);

    assertNotNull(token);
    assertNotNull(jwtParser.parse(token));
  }

  @Test
  void jsonWebToken() {
    String token = Jwts.builder()
        .id(JWT_ID)
        .issuer(ISSUER)
        .subject(SUBJECT)
        .expiration(expiresAt)
        .signWith(privateKey)
        .compact();

    assertNotNull(token);
    assertNotNull(jwtParser.parse(token));
  }

  @Test
  void nimbusJoseJWT() throws JOSEException {
    OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519)
        .keyID(JWT_ID)
        .generate();
    // Create the EdDSA signer
    JWSSigner signer = new Ed25519Signer(jwk);
    // Prepare JWT with claims set
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
        .subject(SUBJECT)
        .issuer(ISSUER)
        .expirationTime(expiresAt)
        .build();
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.getKeyID()).build();
    SignedJWT signedJWT = new SignedJWT(header, claimsSet);
    // Compute the EC signature
    signedJWT.sign(signer);
    // Serialize the JWS to compact form
    String s = signedJWT.serialize();

    assertNotNull(s);
  }

  @Test
  void bitbucketBC() throws JoseException, InvalidJwtException, MalformedClaimException {
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

    String token = jwe.getCompactSerialization();

    assertNotNull(token);

    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
        .setRequireExpirationTime() // the JWT must have an expiration time
        .setRequireSubject() // the JWT must have a subject claim
        .setExpectedIssuer(ISSUER) // whom the JWT needs to have been issued by
        .setExpectedSubject(SUBJECT)
        .setVerificationKey(publicKey)
        .build();
    JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
    // Assert the subject of the JWT is as expected
    assertNotNull(jwtClaims);
    assertEquals(JWT_ID, jwtClaims.getJwtId());
  }
}
