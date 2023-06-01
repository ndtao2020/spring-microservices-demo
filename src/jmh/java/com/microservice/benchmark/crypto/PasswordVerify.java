package com.microservice.benchmark.crypto;

import com.amdelamar.jhash.Hash;
import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.InvalidHashException;
import com.microservice.example.RandomUtils;
import com.microservice.example.crypto.Sha512Hashing;
import com.password4j.Password;
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
@BenchmarkMode({Mode.AverageTime, Mode.SingleShotTime})
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class PasswordVerify {

    static byte[] salt = Sha512Hashing.getSalt();
    static String readPasswordFromUser = RandomUtils.generatePassword(20);
    static char[] readPasswordFromUserChars = readPasswordFromUser.toCharArray();
    static byte[] readPasswordFromUserBytes = readPasswordFromUser.getBytes(StandardCharsets.UTF_8);

    private static final String BCRYPT_PASSWORD_10 = new BCryptPasswordEncoder().encode(readPasswordFromUser);
    private static final byte[] BCRYPT_PASSWORD_BYTES_10 = BCRYPT_PASSWORD_10.getBytes(StandardCharsets.UTF_8);

    private static final String SCRYPT_PASSWORD = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8().encode(readPasswordFromUser);
    private static final byte[] SCRYPT_PASSWORD_BYTES = SCRYPT_PASSWORD.getBytes(StandardCharsets.UTF_8);

    private static final String PBKDF2_PASSWORD = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(readPasswordFromUser);
    private static final byte[] PBKDF2_PASSWORD_BYTES = PBKDF2_PASSWORD.getBytes(StandardCharsets.UTF_8);

    private static final String ARGON2_PASSWORD = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(readPasswordFromUser);
    private static final byte[] ARGON2_PASSWORD_BYTES = ARGON2_PASSWORD.getBytes(StandardCharsets.UTF_8);

    @Benchmark
    public boolean bcryptWithJhash() throws InvalidHashException {
        return Hash.password(readPasswordFromUserChars)
                .salt(salt)
                .algorithm(Type.BCRYPT)
                .verify(BCRYPT_PASSWORD_10);
    }

    @Benchmark
    public boolean bcryptWithPassword4j() {
        return Password.check(readPasswordFromUserBytes, BCRYPT_PASSWORD_BYTES_10).withBcrypt();
    }

    @Benchmark
    public boolean bcryptWithQuarkusSecurity10() {
        return BcryptUtil.matches(readPasswordFromUser, BCRYPT_PASSWORD_10);
    }

    @Benchmark
    public boolean bcryptWithSpringSecurity10() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        // hash a password
        return encoder.matches(readPasswordFromUser, BCRYPT_PASSWORD_10);
    }

    @Benchmark
    public boolean scryptWithJhash() throws InvalidHashException {
        return Hash.password(readPasswordFromUserChars).salt(salt)
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

    @Benchmark
    public boolean pbkdf2WithJhash() throws InvalidHashException {
        return Hash.password(readPasswordFromUserChars).salt(salt).algorithm(Type.PBKDF2_SHA256).verify(PBKDF2_PASSWORD);
    }

    @Benchmark
    public boolean pbkdf2WithPassword4j() {
        return Password.check(readPasswordFromUserBytes, PBKDF2_PASSWORD_BYTES).addSalt(salt).withPBKDF2();
    }

    @Benchmark
    public boolean pbkdf2WithSpringSecurity() {
        // hash a password
        return Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8().matches(readPasswordFromUser, PBKDF2_PASSWORD);
    }

    @Benchmark
    public boolean argon2() {
        return Argon2Factory.create().verify(ARGON2_PASSWORD, readPasswordFromUserBytes);
    }

    @Benchmark
    public boolean argon2WithPassword4j() {
        // hash
        return Password.check(readPasswordFromUserBytes, ARGON2_PASSWORD_BYTES).addSalt(salt).withArgon2();
    }

    @Benchmark
    public boolean argon2WithSpringSecurity() {
        // hash a password
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8().matches(readPasswordFromUser, ARGON2_PASSWORD);
    }
}
