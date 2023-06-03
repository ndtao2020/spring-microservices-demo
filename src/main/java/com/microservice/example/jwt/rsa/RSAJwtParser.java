package com.microservice.example.jwt.rsa;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.microservice.example.jwt.Algorithm;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSAJwtParser {

    private final Base64.Decoder decoder = Base64.getUrlDecoder();
    private final PublicKey publicKey;
    private final Algorithm algorithm;

    public RSAJwtParser(PublicKey publicKey, Algorithm algorithm) {
        this.publicKey = publicKey;
        this.algorithm = algorithm;
    }

    public JSONObject verify(String t) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        String[] r = t.split("\\" + RSAJwtBuilder.DELIMITER);
        byte[] n = r[1].getBytes(StandardCharsets.UTF_8);
        if (!verifySignature(r[0].getBytes(StandardCharsets.UTF_8), n, decoder.decode(r[2]))) {
            throw new SignatureException("Token is invalid !");
        }
        return JSON.parseObject(decoder.decode(n));
    }

    private boolean verifySignature(byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initVerify(publicKey);
        s.update(headerBytes);
        s.update((byte) 46);
        s.update(payloadBytes);
        return s.verify(signatureBytes);
    }
}
