package com.microservice.example.jwt.rsa;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Headers;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAJwtArrayBuilder {

    public static final String DELIMITER = ".";
    protected static final byte[] DELIMITER_BYTES = DELIMITER.getBytes(UTF_8);
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Algorithm algorithm;
    private final byte[] headerBytes;
    private final String headerStr;
    private final RSAPrivateKey privateKey;

    public RSAJwtArrayBuilder(RSAPrivateKey privateKey, Algorithm algorithm) {
        this.privateKey = privateKey;
        this.algorithm = algorithm;
        // handle bytes
        Map<String, String> map = Map.of(Headers.TYPE, "JWT", Headers.ALGORITHM, algorithm.getValue());
        byte[] header = encoder.encode(JSON.toJSONBytes(map));
        byte[] bytes = new byte[header.length + DELIMITER_BYTES.length];
        // copy new array
        System.arraycopy(header, 0, bytes, 0, header.length);
        System.arraycopy(DELIMITER_BYTES, 0, bytes, header.length, DELIMITER_BYTES.length);
        // assign values
        this.headerBytes = bytes;
        this.headerStr = new String(headerBytes, UTF_8) + DELIMITER;
    }

    public String compact(Object payload) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] payloadBytes = encoder.encode(JSON.toJSONBytes(payload));
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update(payloadBytes);
        return headerStr + new String(payloadBytes, UTF_8) + DELIMITER + new String(encoder.encode(s.sign()), UTF_8);
    }

    public String compactArray(Object payload) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] payloadBytes = encoder.encode(JSON.toJSONBytes(payload));
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update(payloadBytes);
        byte[] signatureBytes = encoder.encode(s.sign());
        // init new array
        byte[] bytes = new byte[headerBytes.length + payloadBytes.length + DELIMITER_BYTES.length + signatureBytes.length];
        // copy new array
        System.arraycopy(headerBytes, 0, bytes, 0, headerBytes.length);
        System.arraycopy(payloadBytes, 0, bytes, headerBytes.length, payloadBytes.length);
        System.arraycopy(DELIMITER_BYTES, 0, bytes, headerBytes.length + payloadBytes.length, DELIMITER_BYTES.length);
        System.arraycopy(signatureBytes, 0, bytes, headerBytes.length + payloadBytes.length + DELIMITER_BYTES.length, signatureBytes.length);
        // return token
        return new String(bytes, UTF_8);
    }
}
