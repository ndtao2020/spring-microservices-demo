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

public class RSAJwtBuilder {

  public static final char DELIMITER = '.';
  protected static final byte[] DELIMITER_BYTES = {(byte) 46};
  private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
  private final Algorithm algorithm;
  private final byte[] headerBytes;
  private final String headerStr;
  private final RSAPrivateKey privateKey;

  public RSAJwtBuilder(RSAPrivateKey privateKey, Algorithm algorithm) {
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

  public String compactArray(Object payload) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
    byte[] payloadBytes = encoder.encode(JSON.toJSONBytes(payload));
    final Signature s = Signature.getInstance(algorithm.getJcaName());
    s.initSign(privateKey);
    s.update(headerBytes);
    s.update((byte) 46);
    s.update(payloadBytes);
    byte[] signatureBytes = encoder.encode(s.sign());
    // init new array
    byte[] bytes = new byte[headerBytes.length + DELIMITER_BYTES.length + payloadBytes.length + DELIMITER_BYTES.length + signatureBytes.length];
    // copy new array
    System.arraycopy(headerBytes, 0, bytes, 0, headerBytes.length);
    System.arraycopy(DELIMITER_BYTES, 0, bytes, headerBytes.length, DELIMITER_BYTES.length);
    System.arraycopy(payloadBytes, 0, bytes, headerBytes.length + DELIMITER_BYTES.length, payloadBytes.length);
    System.arraycopy(DELIMITER_BYTES, 0, bytes, headerBytes.length + DELIMITER_BYTES.length + payloadBytes.length, DELIMITER_BYTES.length);
    System.arraycopy(signatureBytes, 0, bytes, headerBytes.length + DELIMITER_BYTES.length + payloadBytes.length + DELIMITER_BYTES.length, signatureBytes.length);
    // return token
    return new String(bytes, UTF_8);
  }
}
