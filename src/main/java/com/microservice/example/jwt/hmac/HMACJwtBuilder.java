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
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class HMACJwtBuilder {

    public static final String DELIMITER = ".";
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final SecretKey secretKey;
    private final Algorithm algorithm;
    private final byte[] headerBytes;
    private final String headerStr;

    public HMACJwtBuilder(String secretKey, Algorithm algorithm) {
        this(secretKey.getBytes(UTF_8), algorithm);
    }

    public HMACJwtBuilder(byte[] secretKeyBytes, Algorithm algorithm) {
        this.secretKey = new SecretKeySpec(secretKeyBytes, algorithm.getJcaName());
        this.algorithm = algorithm;
        Map<String, String> map = Map.of(Headers.TYPE, "JWT", Headers.ALGORITHM, algorithm.getValue());
        this.headerBytes = encoder.encode(JSON.toJSONBytes(map));
        this.headerStr = new String(headerBytes, UTF_8) + DELIMITER;
    }

    public String compact(Map<String, ?> payloadMap) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac m = Mac.getInstance(algorithm.getJcaName());
        m.init(secretKey);
        m.update(headerBytes);
        m.update((byte) 46);
        byte[] bytes = encoder.encode(JSON.toJSONBytes(payloadMap));
        return headerStr + new String(bytes, UTF_8) + DELIMITER + new String(encoder.encode(m.doFinal(bytes)), UTF_8);
    }
}
