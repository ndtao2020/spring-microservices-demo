package com.microservice.example.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.amdelamar.jhash.Hash;
import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.InvalidHashException;
import com.google.common.hash.Hashing;
import com.kosprov.jargon2.api.Jargon2;
import com.kosprov.jargon2.internal.HasherImpl;
import com.kosprov.jargon2.internal.VerifierImpl;
import com.kosprov.jargon2.nativeri.backend.NativeRiJargon2Backend;
import com.microservice.example.RandomUtils;
import com.password4j.Password;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Constants;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Helper;
import io.quarkus.elytron.security.common.BcryptUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Hashing and Verify a Password")
class PasswordHashingTests {

  private static final int BCRYPT_STRENGTH = 12;
  private static final int PBKDF2_SALT_LENGTH = 16;
  private static final int PBKDF2_ITERATIONS = 310000;
  private static final int PBKDF2_HASH_WIDTH = 256; // SHA-256
  private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA" + PBKDF2_HASH_WIDTH; // SHA-256

  static byte[] salt = Sha512Hashing.getSalt();
  static String readPasswordFromUser = RandomUtils.generatePassword(20);
  static char[] readPasswordFromUserChars = readPasswordFromUser.toCharArray();
  static byte[] readPasswordFromUserBytes = readPasswordFromUser.getBytes(StandardCharsets.UTF_8);

  @Test
  void md5() throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    // Add password bytes to digest
    md.update(salt);
    // Get the hash's bytes
    byte[] bytes = md.digest(readPasswordFromUserBytes);
    // asserts
    assertNotNull(bytes);
  }

  @Test
  void md5WithApacheCommons() {
    String md5Hex = DigestUtils.md5Hex(readPasswordFromUser).toUpperCase();
    // asserts
    assertNotNull(md5Hex);
  }

  @Test
  void md5WithGuava() {
    String md5Hex = Hashing.md5().hashString(readPasswordFromUser, StandardCharsets.UTF_8).toString();
    // asserts
    assertNotNull(md5Hex);
  }

  @Test
  void sha512() throws NoSuchAlgorithmException {
    byte[] hash = Sha512Hashing.hash(readPasswordFromUser, salt);
    String securePassword = Sha512Hashing.getSecurePassword(readPasswordFromUser, salt);
    // asserts
    assertNotNull(hash);
    assertNotNull(securePassword);
    // check hex
    assertEquals(Hex.encodeHexString(hash), securePassword);
  }

  @Test
  void sha512WithApacheCommons() {
    byte[] hash = DigestUtils.sha3_512(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
  }

  @Test
  void sha512WithGuava() {
    String hash = Hashing.sha512().hashString(readPasswordFromUser, StandardCharsets.UTF_8).toString();
    // asserts
    assertNotNull(hash);
  }

  // ======================================================

  @Test
  void bcryptWithJhash() throws InvalidHashException {
    Hash jhash = Hash.password(readPasswordFromUserChars).salt(salt).algorithm(Type.BCRYPT);
    String hash = jhash.create();
    assertTrue(jhash.verify(hash));
  }

  @Test
  void bcryptWithPassword4j() {
    // hash
    String hash = Password.hash(readPasswordFromUserBytes).withBcrypt().getResult();
    // verify
    assertTrue(Password.check(readPasswordFromUserBytes, hash.getBytes()).withBcrypt());
  }

  @Test
  void bcryptWithFavrDev() {
    // hash
    String hash = BCrypt.withDefaults().hashToString(10, readPasswordFromUserChars);
    // verify
    BCrypt.Result result = BCrypt.verifyer().verify(readPasswordFromUserChars, hash);
    assertTrue(result.verified);
  }

  @Test
  void mindrotJBCrypt() {
    String hashed = org.mindrot.jbcrypt.BCrypt.hashpw(readPasswordFromUser, org.mindrot.jbcrypt.BCrypt.gensalt());
    assertTrue(org.mindrot.jbcrypt.BCrypt.checkpw(readPasswordFromUser, hashed));
  }

  @Test
  void bcryptWithQuarkusSecurity() {
    // hash a password
    String hash = BcryptUtil.bcryptHash(readPasswordFromUser);
    assertTrue(BcryptUtil.matches(readPasswordFromUser, hash));
  }

  @Test
  void bcryptWithQuarkusSecurityParameters() {
    // hash a password
    String hash = BcryptUtil.bcryptHash(readPasswordFromUser, BCRYPT_STRENGTH);
    assertTrue(BcryptUtil.matches(readPasswordFromUser, hash));
  }

  @Test
  void bcryptWithSpringSecurity() {
    // Create instance
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    // hash a password
    String hash = encoder.encode(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
    assertTrue(encoder.matches(readPasswordFromUser, hash));
  }

  @Test
  void bcryptWithSpringSecurityParameters() {
    // Create instance
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(BCRYPT_STRENGTH);
    // hash a password
    String hash = encoder.encode(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
    assertTrue(encoder.matches(readPasswordFromUser, hash));
  }

  // ======================================================

  @Test
  void scryptWithJhash() throws InvalidHashException {
    Hash jhash = Hash.password(readPasswordFromUserChars).salt(salt).algorithm(Type.SCRYPT);
    String hash = jhash.create();
    assertTrue(jhash.verify(hash));
  }

  @Test
  void scryptWithPassword4j() {
    // hash
    String hash = Password.hash(readPasswordFromUserBytes).addSalt(salt).withScrypt().getResult();
    // verify
    assertTrue(Password.check(readPasswordFromUserBytes, hash.getBytes()).addSalt(salt).withScrypt());
  }

  @Test
  void scryptWithSpringSecurity() {
    // Create instance
    SCryptPasswordEncoder encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
    // hash a password
    String hash = encoder.encode(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
    assertTrue(encoder.matches(readPasswordFromUser, hash));
  }

  // ======================================================

  @Test
  void pbkdf2() throws NoSuchAlgorithmException, InvalidKeySpecException, DecoderException {
    PBKDF2Password pbkdf2Password = new PBKDF2Password(salt);
    // hash a password
    String hash = pbkdf2Password.generatePassword(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
    assertTrue(pbkdf2Password.matches(readPasswordFromUser, hash));
  }

  @Test
  void pbkdf2Parameters() throws NoSuchAlgorithmException, InvalidKeySpecException, DecoderException {
    PBKDF2Password pbkdf2Password = new PBKDF2Password(PBKDF2Password.getSalt(PBKDF2_SALT_LENGTH), PBKDF2_ITERATIONS, PBKDF2_HASH_WIDTH, PBKDF2_ALGORITHM);
    // hash a password
    String hash = pbkdf2Password.generatePassword(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
    assertTrue(pbkdf2Password.matches(readPasswordFromUser, hash));
  }

  @Test
  void pbkdf2WithJhash() throws InvalidHashException {
    Hash jhash = Hash.password(readPasswordFromUserChars).salt(salt).algorithm(Type.PBKDF2_SHA256);
    String hash = jhash.create();
    assertTrue(jhash.verify(hash));
  }

  @Test
  void pbkdf2WithPassword4j() {
    // hash
    String hash = Password.hash(readPasswordFromUserBytes).addSalt(salt).withPBKDF2().getResult();
    // verify
    assertTrue(Password.check(readPasswordFromUserBytes, hash.getBytes()).addSalt(salt).withPBKDF2());
  }

  @Test
  void pbkdf2WithSpringSecurity() {
    // Create instance
    Pbkdf2PasswordEncoder encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    // hash a password
    String hash = encoder.encode(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
    assertTrue(encoder.matches(readPasswordFromUser, hash));
  }

  @Test
  void pbkdf2WithSpringSecurityParameters() {
    // Create instance
    Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder("", PBKDF2_SALT_LENGTH, PBKDF2_ITERATIONS, Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
    // hash a password
    String hash = encoder.encode(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
    assertTrue(encoder.matches(readPasswordFromUser, hash));
  }

  // ======================================================

  @Test
  void argon2() {
    // Create instance
    Argon2 argon2 = Argon2Factory.create();
    // Read password from user
    try {
      // Hash password
      String hash = argon2.hash(10, 65536, 1, readPasswordFromUserBytes);
      // asserts
      assertNotNull(hash);
      assertTrue(argon2.verify(hash, readPasswordFromUserBytes));
    } finally {
      // Wipe confidential data
      argon2.wipeArray(readPasswordFromUserBytes);
    }
  }

  @Test
  void argon2WithHelper() {
    // Create instance
    Argon2 argon2 = Argon2Factory.create();
    // Read password from user
    try {
      // find Iterations
      int iterations = Argon2Helper.findIterations(argon2, 1000, 65536, 1);
      // hash a password
      String hash = argon2.hash(iterations, 65536, 1, readPasswordFromUserBytes);
      // asserts
      assertNotNull(hash);
      assertTrue(argon2.verify(hash, readPasswordFromUserBytes));
    } finally {
      // Wipe confidential data
      argon2.wipeArray(readPasswordFromUserBytes);
    }
  }

  @Test
  void argon2WithJargon2() {
    Jargon2.Hasher hasher = new HasherImpl()
        .type(Jargon2.Type.ARGON2id) // Data-dependent hashing
        .memoryCost(65536)  // 64MB memory cost
        .timeCost(3)        // 3 passes through memory
        .parallelism(4)     // use 4 lanes and 4 threads
        .saltLength(Argon2Constants.DEFAULT_SALT_LENGTH)
        .hashLength(Argon2Constants.DEFAULT_HASH_LENGTH);
    String encodedHash = hasher.password(readPasswordFromUserBytes).encodedHash();
    Jargon2.Verifier verifier = new VerifierImpl()
        .type(Jargon2.Type.ARGON2id) // Data-dependent hashing
        .memoryCost(65536)  // 64MB memory cost
        .timeCost(3)        // 3 passes through memory
        .parallelism(4);
    // asserts
    assertNotNull(encodedHash);
    assertTrue(verifier.hash(encodedHash).password(readPasswordFromUserBytes).verifyEncoded());
  }

  @Test
  void argon2WithJargon2Native() {
    Jargon2.Hasher hasher = new HasherImpl()
        .backend(new NativeRiJargon2Backend())
        .type(Jargon2.Type.ARGON2id) // Data-dependent hashing
        .memoryCost(65536)  // 64MB memory cost
        .timeCost(3)        // 3 passes through memory
        .parallelism(4)     // use 4 lanes and 4 threads
        .saltLength(Argon2Constants.DEFAULT_SALT_LENGTH)
        .hashLength(Argon2Constants.DEFAULT_HASH_LENGTH);
    String encodedHash = hasher.password(readPasswordFromUserBytes).encodedHash();
    Jargon2.Verifier verifier = new VerifierImpl()
        .backend(new NativeRiJargon2Backend())
        .type(Jargon2.Type.ARGON2id) // Data-dependent hashing
        .memoryCost(65536)  // 64MB memory cost
        .timeCost(3)        // 3 passes through memory
        .parallelism(4);
    // asserts
    assertNotNull(encodedHash);
    assertTrue(verifier.hash(encodedHash).password(readPasswordFromUserBytes).verifyEncoded());
  }

  @Test
  void argon2WithPassword4j() {
    // hash
    String hash = Password.hash(readPasswordFromUserBytes).addSalt(salt).withArgon2().getResult();
    // verify
    assertTrue(Password.check(readPasswordFromUserBytes, hash.getBytes()).addSalt(salt).withArgon2());
  }

  @Test
  void argon2WithSpringSecurity() {
    // Create instance
    Argon2PasswordEncoder encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    // hash a password
    String hash = encoder.encode(readPasswordFromUser);
    // asserts
    assertNotNull(hash);
    assertTrue(encoder.matches(readPasswordFromUser, hash));
  }
}
