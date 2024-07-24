package com.microservice.example.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.kosprov.jargon2.api.Jargon2;
import com.kosprov.jargon2.internal.VerifierImpl;
import com.kosprov.jargon2.nativeri.backend.NativeRiJargon2Backend;
import com.microservice.example.RandomUtils;
import com.password4j.Password;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Constants;
import de.mkammerer.argon2.Argon2Factory;
import io.quarkus.elytron.security.common.BcryptUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

// https://cryptobook.nakov.com/mac-and-key-derivation/argon2
@DisplayName("Verify a Password")
class PasswordVerifyTests {

  static String salt = RandomUtils.generatePassword(Argon2Constants.DEFAULT_SALT_LENGTH);
  static byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
  static String readPasswordFromUser = RandomUtils.generatePassword(20);
  private static final String BCRYPT_PASSWORD_10 = new BCryptPasswordEncoder().encode(readPasswordFromUser);
  private static final byte[] BCRYPT_PASSWORD_BYTES_10 = BCRYPT_PASSWORD_10.getBytes(StandardCharsets.UTF_8);

  // ======================================================
  private static final String SCRYPT_PASSWORD = new SCryptPasswordEncoder(65536, 8, 2, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH)
      .encode(readPasswordFromUser);
  private static final byte[] SCRYPT_PASSWORD_BYTES = SCRYPT_PASSWORD.getBytes(StandardCharsets.UTF_8);

  // ======================================================
  private static final String PBKDF2_PASSWORD = new Pbkdf2PasswordEncoder(salt, Argon2Constants.DEFAULT_SALT_LENGTH, 310000, Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256)
      .encode(readPasswordFromUser);
  static char[] readPasswordFromUserChars = readPasswordFromUser.toCharArray();

  // ======================================================
  private static final String ARGON2_PASSWORD = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH)
      .hash(5, 65536, 2, readPasswordFromUserChars);

  // ======================================================
  static byte[] readPasswordFromUserBytes = readPasswordFromUser.getBytes(StandardCharsets.UTF_8);

  // ======================================================

  @Test
  void bcryptWithPassword4j10() {
    assertTrue(Password.check(readPasswordFromUserBytes, BCRYPT_PASSWORD_BYTES_10).withBcrypt());
  }

  @Test
  void bcryptWithFavrDev10() {
    assertTrue(BCrypt.verifyer().verify(readPasswordFromUserChars, BCRYPT_PASSWORD_BYTES_10).verified);
  }

  @Test
  void mindrotJBCrypt10() {
    assertTrue(org.mindrot.jbcrypt.BCrypt.checkpw(readPasswordFromUser, BCRYPT_PASSWORD_10));
  }

  @Test
  void bcryptWithQuarkusSecurity10() {
    assertTrue(BcryptUtil.matches(readPasswordFromUser, BCRYPT_PASSWORD_10));
  }

  @Test
  void bcryptWithSpringSecurity10() {
    assertTrue(new BCryptPasswordEncoder().matches(readPasswordFromUser, BCRYPT_PASSWORD_10));
  }

  // ======================================================

  @Test
  void scryptWithSpringSecurity() {
    SCryptPasswordEncoder passwordEncoder = new SCryptPasswordEncoder(65536, 8, 2, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
    // hash a password
    assertTrue(passwordEncoder.matches(readPasswordFromUser, SCRYPT_PASSWORD));
  }

  // ======================================================

  @Test
  void pbkdf2WithSpringSecurity() {
    Pbkdf2PasswordEncoder passwordEncoder = new Pbkdf2PasswordEncoder(salt, Argon2Constants.DEFAULT_SALT_LENGTH, 310000, Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
    // hash a password
    assertTrue(passwordEncoder.matches(readPasswordFromUser, PBKDF2_PASSWORD));
  }

  // ======================================================

  @Test
  void argon2() {
    Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH);
    assertTrue(argon2.verify(ARGON2_PASSWORD, readPasswordFromUserBytes));
  }

  @Test
  void argon2WithJargon2() {
    Jargon2.Verifier verifier = new VerifierImpl().type(Jargon2.Type.ARGON2id).memoryCost(65536).parallelism(2);
    // asserts
    assertTrue(verifier.hash(ARGON2_PASSWORD).password(readPasswordFromUserBytes).verifyEncoded());
  }

  @Test
  void argon2WithJargon2Native() {
    Jargon2.Verifier verifier = new VerifierImpl().backend(new NativeRiJargon2Backend()).type(Jargon2.Type.ARGON2id).memoryCost(65536).parallelism(2);
    // asserts
    assertTrue(verifier.hash(ARGON2_PASSWORD).password(readPasswordFromUserBytes).verifyEncoded());
  }

  @Test
  void argon2WithSpringSecurity() {
    Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder(Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH, 2, 65536, 5);
    // hash a password
    assertTrue(passwordEncoder.matches(readPasswordFromUser, ARGON2_PASSWORD));
  }
}
