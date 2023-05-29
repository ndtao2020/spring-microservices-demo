package com.microservice.example.jwt.rsa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Map;
import java.util.UUID;

public class JwtUtil {

    private static final String KEY_ID = "a";
    private static final String KEY_EXP = "exp";

    private final JwtBuilder b;
    private final JwtParser p;

    public JwtUtil(ObjectMapper mapper, String keyStoreFile, String keyAlias, String keyPassword) {
        KeyPair keyPair = new RSAUtil().getKeyPair(keyStoreFile, keyPassword, keyAlias);
        this.b = new JwtBuilder(mapper, keyPair.getPrivate());
        this.p = new JwtParser(mapper, keyPair.getPublic());
    }

    private Long millisToDate(long timeStamp) {
        return System.currentTimeMillis() / 1000 + timeStamp;
    }

    public String build(Map<String, ?> claims) {
        try {
            return b.compact(claims);
        } catch (JsonProcessingException | SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public String builderTokenToVerify(UUID id) {
        return build(Map.of(KEY_ID, id, KEY_EXP, millisToDate(1800)));
    }

    public JsonNode validate(String t) {
        JsonNode j = p.verify(t);
        if (System.currentTimeMillis() / 1000 > j.get(KEY_EXP).longValue()) {
            throw new IllegalArgumentException("Token has expired !");
        }
        return j;
    }
}
