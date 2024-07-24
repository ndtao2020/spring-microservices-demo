package com.microservice.example.crypto;

import lombok.experimental.UtilityClass;
import lombok.extern.log4j.Log4j2;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

@Log4j2
@UtilityClass
public class AesAlgorithm {

  private final String TRANSFORMATION = "AES/GCM/NoPadding";
  private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
  private final Base64.Decoder decoder = Base64.getUrlDecoder();

  private SecretKey generateSecretKey(String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(salt.toCharArray(), salt.getBytes(UTF_8), 65536, 256);
    SecretKey secretKey = factory.generateSecret(spec);
    return new SecretKeySpec(secretKey.getEncoded(), "AES");
  }

  private GCMParameterSpec generateGCMParameterSpec(String salt) {
    return new GCMParameterSpec(128, salt.getBytes(UTF_8));
  }

  public String encrypt(String plainText, String salt) throws NoSuchAlgorithmException, IllegalBlockSizeException,
      BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException {
    if (plainText == null) return null;
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, generateSecretKey(salt), generateGCMParameterSpec(salt));
    return encoder.encodeToString(cipher.doFinal(plainText.getBytes(UTF_8)));
  }

  public String decrypt(String plainText, String salt) throws NoSuchPaddingException, NoSuchAlgorithmException,
      BadPaddingException, InvalidKeySpecException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
    if (plainText == null) return null;
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, generateSecretKey(salt), generateGCMParameterSpec(salt));
    return new String(cipher.doFinal(decoder.decode(plainText)), UTF_8);
  }
}
