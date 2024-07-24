package com.microservice.benchmark.crypto;

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
import org.openjdk.jmh.annotations.*;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class PasswordVerify {

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

  // ======================================================

  @Benchmark
  public boolean bcryptWithPassword4j() {
    return Password.check(readPasswordFromUserBytes, BCRYPT_PASSWORD_BYTES_10).withBcrypt();
  }

  @Benchmark
  public boolean bcryptWithFavrDev10() {
    return BCrypt.verifyer().verify(readPasswordFromUserChars, BCRYPT_PASSWORD_BYTES_10).verified;
  }

  @Benchmark
  public boolean mindrotJBCrypt10() {
    return org.mindrot.jbcrypt.BCrypt.checkpw(readPasswordFromUser, BCRYPT_PASSWORD_10);
  }

  @Benchmark
  public boolean bcryptWithQuarkusSecurity10() {
    return BcryptUtil.matches(readPasswordFromUser, BCRYPT_PASSWORD_10);
  }

  @Benchmark
  public boolean bcryptWithSpringSecurity10() {
    return new BCryptPasswordEncoder().matches(readPasswordFromUser, BCRYPT_PASSWORD_10);
  }

  // ======================================================

  @Benchmark
  public boolean scryptWithSpringSecurity() {
    SCryptPasswordEncoder passwordEncoder = new SCryptPasswordEncoder(65536, 8, 2, Argon2Constants.DEFAULT_HASH_LENGTH, Argon2Constants.DEFAULT_SALT_LENGTH);
    // hash a password
    return passwordEncoder.matches(readPasswordFromUser, SCRYPT_PASSWORD);
  }

  // ======================================================

  @Benchmark
  public boolean pbkdf2WithSpringSecurity() {
    Pbkdf2PasswordEncoder passwordEncoder = new Pbkdf2PasswordEncoder(salt, Argon2Constants.DEFAULT_SALT_LENGTH, 310000, Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
    // hash a password
    return passwordEncoder.matches(readPasswordFromUser, PBKDF2_PASSWORD);
  }

  // ======================================================

  @Benchmark
  public boolean argon2() {
    Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH);
    return argon2.verify(ARGON2_PASSWORD, readPasswordFromUserBytes);
  }

  @Benchmark
  public boolean argon2WithJargon2() {
    Jargon2.Verifier verifier = new VerifierImpl().type(Jargon2.Type.ARGON2id).memoryCost(65536).parallelism(2);
    // asserts
    return verifier.hash(ARGON2_PASSWORD).password(readPasswordFromUserBytes).verifyEncoded();
  }

  @Benchmark
  public boolean argon2WithJargon2Native() {
    Jargon2.Verifier verifier = new VerifierImpl().backend(new NativeRiJargon2Backend()).type(Jargon2.Type.ARGON2id).memoryCost(65536).parallelism(2);
    // asserts
    return verifier.hash(ARGON2_PASSWORD).password(readPasswordFromUserBytes).verifyEncoded();
  }

  @Benchmark
  public boolean argon2WithSpringSecurity() {
    Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder(Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH, 1, 16, 2);
    return passwordEncoder.matches(readPasswordFromUser, ARGON2_PASSWORD);
  }
}
