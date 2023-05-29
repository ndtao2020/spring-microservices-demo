package com.microservice.example.jwt.rsa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.*;
import java.util.Base64;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JwtBuilder {

    public static final String DELIMITER = ".";
    private static final int LENGTH = 512;
    protected static final String RSA_ALGORITHM = "SHA" + LENGTH + "withRSA";
    protected static final String HMAC_ALGORITHM = "HmacSHA" + LENGTH;
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final ObjectMapper a;
    private final String header;
    private final PrivateKey privateKey;

    public JwtBuilder(ObjectMapper mapper, PrivateKey privateKey) {
        try {
            this.a = mapper;
            this.header = new String(encoder.encode(toJson(Map.of("alg", "RS" + LENGTH, "typ", "JWT"))), UTF_8);
            this.privateKey = privateKey;
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public String compact(Map<String, ?> c) throws JsonProcessingException, SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        String payload = new String(encoder.encode(toJson(c)), UTF_8);
        return header + DELIMITER + payload + DELIMITER + sign(header, payload);
    }

    private byte[] toJson(Map<String, ?> data) throws JsonProcessingException {
        return a.writeValueAsBytes(data);
    }

    private String sign(String header, String payload) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        final Signature signature = Signature.getInstance(RSA_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(header.getBytes(UTF_8));
        signature.update((byte) 46);
        signature.update(payload.getBytes(UTF_8));
        return new String(encoder.encode(signature.sign()), UTF_8);
    }
}
