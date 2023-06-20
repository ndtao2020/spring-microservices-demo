package com.microservice.example.jwt.rsa;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Headers;
import com.microservice.example.jwt.Payload;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAJwtBuilder {

    public static final String DELIMITER = ".";
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Algorithm algorithm;
    private final byte[] headerBytes;
    private final String headerStr;
    private final RSAPrivateKey privateKey;

    public RSAJwtBuilder(RSAPrivateKey privateKey, Algorithm algorithm) {
        this.privateKey = privateKey;
        this.algorithm = algorithm;
        Map<String, String> map = Map.of(Headers.TYPE, "JWT", Headers.ALGORITHM, algorithm.getValue());
        this.headerBytes = encoder.encode(JSON.toJSONBytes(map));
        this.headerStr = new String(headerBytes, UTF_8) + DELIMITER;
    }

    public String compact(Payload payload) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] bytes = encoder.encode(JSON.toJSONBytes(payload));
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update((byte) 46);
        s.update(bytes);
        return headerStr + new String(bytes, UTF_8) + DELIMITER + new String(encoder.encode(s.sign()), UTF_8);
    }

    public String compact(Map<String, ?> payloadMap) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] bytes = encoder.encode(JSON.toJSONBytes(payloadMap));
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update((byte) 46);
        s.update(bytes);
        return headerStr + new String(bytes, UTF_8) + DELIMITER + new String(encoder.encode(s.sign()), UTF_8);
    }
}
