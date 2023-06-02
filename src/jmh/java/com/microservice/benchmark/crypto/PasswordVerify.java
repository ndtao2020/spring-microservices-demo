package com.microservice.benchmark.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.amdelamar.jhash.Hash;
import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.InvalidHashException;
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
    private static final String PBKDF2_PASSWORD = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(readPasswordFromUser);
    private static final byte[] PBKDF2_PASSWORD_BYTES = PBKDF2_PASSWORD.getBytes(StandardCharsets.UTF_8);
    static char[] readPasswordFromUserChars = readPasswordFromUser.toCharArray();
    private static final String ARGON2_PASSWORD = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH)
            .hash(2, 16, 1, readPasswordFromUserChars);
    static byte[] readPasswordFromUserBytes = readPasswordFromUser.getBytes(StandardCharsets.UTF_8);
    private static final String SCRYPT_PASSWORD = Password.hash(readPasswordFromUserBytes).addSalt(saltBytes).withScrypt().getResult();
    private static final byte[] SCRYPT_PASSWORD_BYTES = SCRYPT_PASSWORD.getBytes(StandardCharsets.UTF_8);

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
    public boolean bcryptWithQuarkusSecurity10() {
        return BcryptUtil.matches(readPasswordFromUser, BCRYPT_PASSWORD_10);
    }

    @Benchmark
    public boolean bcryptWithSpringSecurity10() {
        return new BCryptPasswordEncoder().matches(readPasswordFromUser, BCRYPT_PASSWORD_10);
    }

    // ======================================================

    @Benchmark
    public boolean scryptWithJhash() throws InvalidHashException {
        return Hash.password(readPasswordFromUserChars).salt(saltBytes)
                .algorithm(Type.SCRYPT).verify(SCRYPT_PASSWORD);
    }

    @Benchmark
    public boolean scryptWithPassword4j() {
        return Password.check(readPasswordFromUserBytes, SCRYPT_PASSWORD_BYTES)
                .addSalt(salt).withScrypt();
    }

    @Benchmark
    public boolean scryptWithSpringSecurity() {
        // hash a password
        return SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8()
                .matches(readPasswordFromUser, SCRYPT_PASSWORD);
    }

    // ======================================================

    @Benchmark
    public boolean pbkdf2WithJhash() throws InvalidHashException {
        return Hash.password(readPasswordFromUserChars).salt(saltBytes).algorithm(Type.PBKDF2_SHA256).verify(PBKDF2_PASSWORD);
    }

    @Benchmark
    public boolean pbkdf2WithPassword4j() {
        return Password.check(readPasswordFromUserBytes, PBKDF2_PASSWORD_BYTES).addSalt(saltBytes).withPBKDF2();
    }

    @Benchmark
    public boolean pbkdf2WithSpringSecurity() {
        // hash a password
        return Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8().matches(readPasswordFromUser, PBKDF2_PASSWORD);
    }

    // ======================================================

    @Benchmark
    public boolean argon2() {
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH);
        return argon2.verify(ARGON2_PASSWORD, readPasswordFromUserBytes);
    }

    @Benchmark
    public boolean argon2WithSpringSecurity() {
        Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder(Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH, 1, 16, 2);
        return passwordEncoder.matches(readPasswordFromUser, ARGON2_PASSWORD);
    }
}
