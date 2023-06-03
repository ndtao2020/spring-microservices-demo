package com.microservice.benchmark.jwt.rsa;

import com.alibaba.fastjson2.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.rsa.RSAJwtParser;
import io.fusionauth.jwt.rsa.RSAVerifier;
import org.openjdk.jmh.annotations.*;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
    private RSAPrivateKey privateKey;
    private String generatedToken;

    @Setup
    public void setup() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        // assign variables
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // generate a token
        generatedToken = JWT.create()
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + (60 * 60 * 1000)))
                .sign(Algorithm.RSA256(publicKey, privateKey));
    }

    @Benchmark
    public JSONObject customJWT() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        RSAJwtParser jwtParser = new RSAJwtParser(publicKey, com.microservice.example.jwt.Algorithm.RS256);
        return jwtParser.verify(generatedToken);
    }

    @Benchmark
    public JWTVerifier auth0JWT() {
        return JWT.require(Algorithm.RSA256(publicKey, privateKey))
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .build();
    }

    @Benchmark
    public io.fusionauth.jwt.domain.JWT fusionAuth() {
        // Sign and encode the JWT to a JSON string representation
        return io.fusionauth.jwt.domain.JWT.getDecoder().decode(generatedToken, RSAVerifier.newVerifier(publicKey));
    }
}
