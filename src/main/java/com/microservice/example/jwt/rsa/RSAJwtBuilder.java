package com.microservice.example.jwt.rsa;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Headers;

import java.security.*;
import java.util.Base64;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAJwtBuilder {

    public static final String DELIMITER = ".";
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Algorithm algorithm;
    private final byte[] headerBytes;
    private final String headerStr;
    private final PrivateKey privateKey;

    public RSAJwtBuilder(PrivateKey privateKey, Algorithm algorithm) {
        this.privateKey = privateKey;
        this.algorithm = algorithm;
        Map<String, String> map = Map.of(Headers.TYPE, "JWT", Headers.ALGORITHM, algorithm.getValue());
        this.headerBytes = encoder.encode(JSON.toJSONBytes(map));
        this.headerStr = new String(headerBytes, UTF_8) + DELIMITER;
    }

    public String compact(Map<String, ?> payloadMap) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] payloadBytes = encoder.encode(JSON.toJSONBytes(payloadMap));
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update((byte) 46);
        s.update(payloadBytes);
        return headerStr + new String(payloadBytes, UTF_8) + DELIMITER + new String(encoder.encode(s.sign()), UTF_8);
    }
}
