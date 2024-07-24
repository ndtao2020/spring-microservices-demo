package com.microservice.example.jwt.eddsa;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Payload;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPublicKey;
import java.util.Base64;

public class EdDSAJwtParser {

  private final Base64.Decoder decoder = Base64.getUrlDecoder();
  private final EdECPublicKey publicKey;
  private final Algorithm algorithm;

  public EdDSAJwtParser(EdECPublicKey publicKey, Algorithm algorithm) {
    this.publicKey = publicKey;
    this.algorithm = algorithm;
  }

  public Payload verify(String t) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
    String[] r = t.split("\\" + EdDSAJwtBuilder.DELIMITER);
    byte[] n = r[1].getBytes(StandardCharsets.UTF_8);
    if (!verifySignature(r[0].getBytes(StandardCharsets.UTF_8), n, decoder.decode(r[2]))) {
      throw new SignatureException("Token is invalid !");
    }
    Payload payload = JSON.parseObject(decoder.decode(n), Payload.class);
    if (payload.getExp() < System.currentTimeMillis() / 1000) {
      throw new SignatureException("Token is expiration !");
    }
    return payload;
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
