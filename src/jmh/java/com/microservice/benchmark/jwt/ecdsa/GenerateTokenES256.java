package com.microservice.benchmark.jwt.ecdsa;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Claims;
import com.microservice.example.jwt.Payload;
import com.microservice.example.jwt.ecdsa.ECDSAJwtBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.ec.ECSigner;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.openjdk.jmh.annotations.*;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class GenerateTokenES256 {

    private static final String JWT_ID = RandomUtils.generateId(20);
    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";

    private final Date expiresAt = new Date(System.currentTimeMillis() + (60 * 60 * 1000));
    private final NumericDate numericDate = NumericDate.fromMilliseconds(expiresAt.getTime());
    private final ZonedDateTime zoneExpiresAt = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(60);

    private ECPrivateKey privateKey;

    @Setup
    public void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        // assign variables
        privateKey = (ECPrivateKey) keyPair.getPrivate();
    }

    @Benchmark
    public String customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        ECDSAJwtBuilder jwtBuilder = new ECDSAJwtBuilder(privateKey, com.microservice.example.jwt.Algorithm.ES256);

        Map<String, Object> map = new HashMap<>();
        map.put(Claims.JWT_ID, JWT_ID);
        map.put(Claims.ISSUER, ISSUER);
        map.put(Claims.SUBJECT, SUBJECT);
        map.put(Claims.EXPIRES_AT, expiresAt.getTime() / 1000);

        return jwtBuilder.compact(map);
    }

    @Benchmark
    public String customJWTwithDTO() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        ECDSAJwtBuilder jwtBuilder = new ECDSAJwtBuilder(privateKey, com.microservice.example.jwt.Algorithm.ES256);

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
                .sign(Algorithm.ECDSA256(privateKey));
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
        signedJWT.sign(new ECDSASigner(privateKey));
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
        return io.fusionauth.jwt.domain.JWT.getEncoder().encode(jwt, ECSigner.newSHA256Signer(privateKey));
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
        jwe.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jwe.setKey(privateKey);

        return jwe.getCompactSerialization();
    }
}
