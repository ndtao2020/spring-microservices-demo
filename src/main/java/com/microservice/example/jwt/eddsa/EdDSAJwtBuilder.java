package com.microservice.example.jwt.eddsa;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Headers;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.util.Base64;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

// https://curity.io/resources/learn/sign-tokens-with-eddsa/?tab=Decoded-JWT
public class EdDSAJwtBuilder {

  public static final char DELIMITER = '.';
  private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
  private final Algorithm algorithm;
  private final byte[] headerBytes;
  private final String headerStr;
  private final EdECPrivateKey privateKey;

  public EdDSAJwtBuilder(EdECPrivateKey privateKey, Algorithm algorithm) {
    this.privateKey = privateKey;
    this.algorithm = algorithm;
    Map<String, String> map = Map.of(Headers.TYPE, "JWT", Headers.ALGORITHM, algorithm.getValue());
    this.headerBytes = encoder.encode(JSON.toJSONBytes(map));
    this.headerStr = new String(headerBytes, UTF_8) + DELIMITER;
  }

  public String compact(Object payload) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
    byte[] bytes = encoder.encode(JSON.toJSONBytes(payload));
    final Signature s = Signature.getInstance(algorithm.getJcaName());
    s.initSign(privateKey);
    s.update(headerBytes);
    s.update((byte) 46);
    s.update(bytes);
    return headerStr + new String(bytes, UTF_8) + DELIMITER + new String(encoder.encode(s.sign()), UTF_8);
  }
}
