package com.microservice.example.jwt.hmac;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

public class JwtParser {

    private final Base64.Decoder decoder = Base64.getUrlDecoder();
    private final ObjectMapper mapper = new ObjectMapper();
    private final SecretKey secretKey;
    private final Algorithm algorithm;

    public JwtParser(String secretKey, Algorithm algorithm) {
        this(secretKey.getBytes(UTF_8), algorithm);
    }

    public JwtParser(byte[] secretKeyBytes, Algorithm algorithm) {
        this.secretKey = new SecretKeySpec(secretKeyBytes, algorithm.getJcaName());
        this.algorithm = algorithm;
    }

    public JsonNode verify(String t) {
        try {
            String[] r = t.split("\\" + com.microservice.example.jwt.rsa.JwtBuilder.DELIMITER);
            byte[] n = r[1].getBytes(StandardCharsets.UTF_8);
            if (!verifySignature(r[0].getBytes(StandardCharsets.UTF_8), n, decoder.decode(r[2]))) {
                throw new SignatureException("Token is invalid !");
            }
            return mapper.readTree(decoder.decode(n));
        } catch (Exception e) {
            throw new SecurityException(e.getMessage());
        }
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
