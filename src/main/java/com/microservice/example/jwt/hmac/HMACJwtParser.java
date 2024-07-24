package com.microservice.example.jwt.hmac;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Payload;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
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

  public Payload verify(String token) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    String[] r = token.split("\\" + HMACJwtBuilder.DELIMITER);
    byte[] n = r[1].getBytes(UTF_8);
    if (!verifySignature(r[0].getBytes(UTF_8), n, decoder.decode(r[2]))) {
      throw new SignatureException("Token is invalid !");
    }
    Payload payload = JSON.parseObject(decoder.decode(n), Payload.class);
    if (payload.getExp() < System.currentTimeMillis() / 1000) {
      throw new SignatureException("Token is expiration !");
    }
    return payload;
  }

  private boolean verifySignature(byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
    final Mac m = Mac.getInstance(algorithm.getJcaName());
    m.init(secretKey);
    m.update(headerBytes);
    m.update((byte) 46);
    return MessageDigest.isEqual(m.doFinal(payloadBytes), signatureBytes);
  }
}
