package com.microservice.benchmark.jwt.rsa;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Claims;
import com.microservice.example.jwt.rsa.RSAJwtBuilder;
import io.fusionauth.jwt.rsa.RSASigner;
import org.jose4j.jwt.NumericDate;
import org.openjdk.jmh.annotations.*;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

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

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    @Setup
    public void setup() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        // assign variables
        publicKey = (RSAPublicKey) keyPair.getPublic();
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
    public String auth0JWT() {
        return JWT.create()
                .withJWTId(JWT_ID)
                .withIssuer(ISSUER)
                .withSubject(SUBJECT)
                .withExpiresAt(expiresAt)
                .sign(Algorithm.RSA256(publicKey, privateKey));
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
}
