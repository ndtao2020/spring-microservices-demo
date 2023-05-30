package com.microservice.example.jwt.hmac;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.microservice.example.jwt.Algorithm;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class HMACJwtParser {

    private final Base64.Decoder decoder = Base64.getUrlDecoder();
    private final SecretKey secretKey;
    private final Algorithm algorithm;

    public HMACJwtParser(String secretKey, Algorithm algorithm) {
        this(secretKey.getBytes(UTF_8), algorithm);
    }

    public HMACJwtParser(byte[] secretKeyBytes, Algorithm algorithm) {
        this.secretKey = new SecretKeySpec(secretKeyBytes, algorithm.getJcaName());
        this.algorithm = algorithm;
    }

    public JSONObject verify(String token) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String[] r = token.split("\\" + HMACJwtBuilder.DELIMITER);
        byte[] n = r[1].getBytes(StandardCharsets.UTF_8);
        if (!verifySignature(r[0].getBytes(StandardCharsets.UTF_8), n, decoder.decode(r[2]))) {
            throw new SignatureException("Token is invalid !");
        }
        return JSON.parseObject(decoder.decode(n));
    }

    private boolean verifySignature(byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.getJcaName());
        mac.init(secretKey);
        mac.update(headerBytes);
        mac.update((byte) 46);
        mac.update(payloadBytes);
        return Arrays.equals(signatureBytes, mac.doFinal());
    }
}
