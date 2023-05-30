package com.microservice.example.jwt.hmac;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Headers;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class HMACJwtBuilder {

    public static final String DELIMITER = ".";
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final SecretKey secretKey;
    private final Algorithm algorithm;

    public HMACJwtBuilder(String secretKey, Algorithm algorithm) {
        this(secretKey.getBytes(UTF_8), algorithm);
    }

    public HMACJwtBuilder(byte[] secretKeyBytes, Algorithm algorithm) {
        this.secretKey = new SecretKeySpec(secretKeyBytes, algorithm.getJcaName());
        this.algorithm = algorithm;
    }

    public String compact(Map<String, ?> payloadMap) throws NoSuchAlgorithmException, InvalidKeyException {
        Map<String, Object> map = new HashMap<>();
        map.put(Headers.TYPE, "JWT");
        map.put(Headers.ALGORITHM, algorithm.getValue());
        // update
        byte[] headerBytes = encoder.encode(JSON.toJSONBytes(map));
        byte[] payloadBytes = encoder.encode(JSON.toJSONBytes(payloadMap));
        // create str
        return new String(headerBytes, UTF_8) + DELIMITER + new String(payloadBytes, UTF_8) + DELIMITER + hash(headerBytes, payloadBytes);
    }

    private String hash(byte[] headerBytes, byte[] payloadBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.getJcaName());
        mac.init(secretKey);
        mac.update(headerBytes);
        mac.update((byte) 46);
        mac.update(payloadBytes);
        return new String(encoder.encode(mac.doFinal()), UTF_8);
    }
}
