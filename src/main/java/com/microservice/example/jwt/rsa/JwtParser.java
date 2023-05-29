package com.microservice.example.jwt.rsa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class JwtParser {

    private final Base64.Decoder decoder = Base64.getUrlDecoder();
    private final ObjectMapper a;
    private final PublicKey p;

    public JwtParser(ObjectMapper mapper, PublicKey publicKey) {
        this.a = mapper;
        this.p = publicKey;
    }

    public JsonNode verify(String t) {
        try {
            String[] r = t.split("\\" + JwtBuilder.DELIMITER);
            byte[] n = r[1].getBytes(StandardCharsets.UTF_8);
            if (!verifySignature(r[0].getBytes(StandardCharsets.UTF_8), n, decoder.decode(r[2]))) {
                throw new SignatureException("Token is invalid !");
            }
            return a.readTree(decoder.decode(n));
        } catch (Exception e) {
            throw new SecurityException(e.getMessage());
        }
    }

    private boolean verifySignature(byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        Signature s = Signature.getInstance(JwtBuilder.RSA_ALGORITHM);
        s.initVerify(p);
        s.update(headerBytes);
        s.update((byte) 46);
        s.update(payloadBytes);
        return s.verify(signatureBytes);
    }
}
