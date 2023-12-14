package com.microservice.benchmark.jwt.ecdsa;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Payload;
import com.microservice.example.jwt.ecdsa.ECDSAJwtParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.fusionauth.jwt.ec.ECVerifier;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class VerifyTokenES256 {

    private static final String JWT_ID = RandomUtils.generateId(20);
    private static final String ISSUER = "https://taoqn.pages.dev";
    private static final String SUBJECT = "ndtao2020";

    private ECPublicKey publicKey;
    private String generatedToken;

    @Setup
    public void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        // assign variables
        publicKey = (ECPublicKey) keyPair.getPublic();
        // generate a token
        generatedToken = JWT.create()
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
                .sign(Algorithm.ECDSA256((ECPrivateKey) keyPair.getPrivate()));
    }

    @Benchmark
    public Payload customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        ECDSAJwtParser jwtParser = new ECDSAJwtParser(publicKey, com.microservice.example.jwt.Algorithm.ES256);
        return jwtParser.verify(generatedToken);
    }

    @Benchmark
    public JWTVerifier auth0JWT() {
        return JWT.require(Algorithm.ECDSA256(publicKey))
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
        if (!signedJWT.verify(new ECDSAVerifier(publicKey))) {
            throw new SignatureException("Token is invalid !");
        }
        return signedJWT.getJWTClaimsSet();
    }

    @Benchmark
    public io.fusionauth.jwt.domain.JWT fusionAuth() {
        // Sign and encode the JWT to a JSON string representation
        return io.fusionauth.jwt.domain.JWT.getDecoder().decode(generatedToken, ECVerifier.newVerifier(publicKey));
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
}
