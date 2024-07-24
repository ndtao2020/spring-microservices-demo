package com.microservice.example.crypto;

import lombok.extern.log4j.Log4j2;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

@Log4j2
public class PBKDF2Password {

  // Pick an iteration count that works for you. The NIST recommends at
  // least 1,000 iterations:
  // http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
  // iOS 4.x reportedly uses 10,000:
  // http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords/
  private static final int PBKDF2_SALT_LENGTH = 16;
  private static final int PBKDF2_ITERATIONS = 65536;
  private static final int PBKDF2_HASH_WIDTH = 256; // SHA-256
  private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA" + PBKDF2_HASH_WIDTH; // SHA-256

  private final byte[] salt;
  private final int iterations;
  private final int keyLength;
  private final String alg;

  public PBKDF2Password() throws NoSuchAlgorithmException {
    this(getSalt(PBKDF2_SALT_LENGTH));
  }

  public PBKDF2Password(byte[] salt) {
    this(salt, PBKDF2_ITERATIONS, PBKDF2_HASH_WIDTH, PBKDF2_ALGORITHM);
  }

  public PBKDF2Password(byte[] salt, int iterations, int keyLength, String alg) {
    this.salt = salt;
    this.iterations = iterations;
    this.keyLength = keyLength;
    this.alg = alg;
  }

  public static byte[] getSalt(int length) throws NoSuchAlgorithmException {
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    byte[] salt = new byte[length];
    sr.nextBytes(salt);
    return salt;
  }

  public byte[] hashPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
    SecretKeyFactory skf = SecretKeyFactory.getInstance(alg);
    return skf.generateSecret(spec).getEncoded();
  }

  public String generatePassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] hash = hashPassword(password);
    return Hex.encodeHexString(hash);
  }

  public boolean matches(String rawPassword, String encodedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException, DecoderException {
    return Arrays.equals(Hex.decodeHex(encodedPassword), hashPassword(rawPassword));
  }
}
