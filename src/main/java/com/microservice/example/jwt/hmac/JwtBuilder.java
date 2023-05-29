package com.microservice.example.jwt.hmac;

import com.dslplatform.json.DslJson;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Headers;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JwtBuilder {

    public static final String DELIMITER = ".";
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final DslJson<Object> json = new DslJson<>();
    private final SecretKey secretKey;
    private final Algorithm algorithm;

    public JwtBuilder(String secretKey, Algorithm algorithm) {
        this(secretKey.getBytes(UTF_8), algorithm);
    }

    public JwtBuilder(byte[] secretKeyBytes, Algorithm algorithm) {
        this.secretKey = new SecretKeySpec(secretKeyBytes, algorithm.getJcaName());
        this.algorithm = algorithm;
    }

    private byte[] toJson(Map<String, ?> data) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            json.serialize(data, stream);
            return stream.toByteArray();
        } catch (IOException e) {
            throw new IOException(e);
        }
    }

    public String compact(Map<String, ?> payloadMap) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        Map<String, Object> map = new HashMap<>();
        map.put(Headers.TYPE, "JWT");
        map.put(Headers.ALGORITHM, algorithm.getValue());
        // update
        String header = new String(encoder.encode(toJson(map)), UTF_8);
        String payload = new String(encoder.encode(toJson(payloadMap)), UTF_8);
        return header + DELIMITER + payload + DELIMITER + hash(header, payload);
    }

    private String hash(String header, String payload) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.getJcaName());
        mac.init(secretKey);
        mac.update(header.getBytes(UTF_8));
        mac.update((byte) 46);
        mac.update(payload.getBytes(UTF_8));
        return new String(encoder.encode(mac.doFinal()), UTF_8);
    }
}
