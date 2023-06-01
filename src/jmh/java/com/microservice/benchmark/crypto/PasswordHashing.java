package com.microservice.benchmark.crypto;

import com.amdelamar.jhash.Hash;
import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.InvalidHashException;
import com.google.common.hash.Hashing;
import com.microservice.example.RandomUtils;
import com.microservice.example.crypto.PBKDF2Password;
import com.microservice.example.crypto.Sha512Hashing;
import com.password4j.Password;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Helper;
import io.quarkus.elytron.security.common.BcryptUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.openjdk.jmh.annotations.*;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode({Mode.AverageTime, Mode.SingleShotTime})
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class PasswordHashing {

    private static final int PBKDF2_SALT_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 310000;
    private static final int PBKDF2_HASH_WIDTH = 256; // SHA-256
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA" + PBKDF2_HASH_WIDTH; // SHA-256

    static byte[] salt = Sha512Hashing.getSalt();
    static String readPasswordFromUser = RandomUtils.generatePassword(20);
    static char[] readPasswordFromUserChars = readPasswordFromUser.toCharArray();
    static byte[] readPasswordFromUserBytes = readPasswordFromUser.getBytes(StandardCharsets.UTF_8);

    @Benchmark
    public String md5() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        // Add password bytes to digest
        md.update(salt);
        // Get the hash's bytes
        return Hex.encodeHexString(md.digest(readPasswordFromUserBytes));
    }

    @Benchmark
    public String md5WithApacheCommons() {
        return DigestUtils.md5Hex(readPasswordFromUser).toUpperCase();
    }

    @Benchmark
    public String md5WithGuava() {
        return Hashing.md5().hashString(readPasswordFromUser, StandardCharsets.UTF_8).toString();
    }

    @Benchmark
    public String sha512() {
        return Sha512Hashing.getSecurePassword(readPasswordFromUser, salt);
    }

    @Benchmark
    public String sha512WithApacheCommons() {
        return DigestUtils.sha3_512Hex(readPasswordFromUser);
    }

    @Benchmark
    public String sha512WithGuava() {
        return Hashing.sha512().hashString(readPasswordFromUser, StandardCharsets.UTF_8).toString();
    }

    @Benchmark
    public String bcryptWithJhash() {
        return Hash.password(readPasswordFromUserChars).salt(salt).algorithm(Type.BCRYPT).create();
    }

    @Benchmark
    public String bcryptWithPassword4j() {
        return Password.hash(readPasswordFromUserBytes).withBcrypt().getResult();
    }

    @Benchmark
    public String bcryptWithQuarkusSecurity8() {
        // hash a password
        return BcryptUtil.bcryptHash(readPasswordFromUser, 8);
    }

    @Benchmark
    public String bcryptWithQuarkusSecurity10() {
        return BcryptUtil.bcryptHash(readPasswordFromUser, 10);
    }

    @Benchmark
    public String bcryptWithQuarkusSecurity12() {
        // hash a password
        return BcryptUtil.bcryptHash(readPasswordFromUser, 12);
    }

    @Benchmark
    public String bcryptWithSpringSecurity8() {
        // hash a password
        return new BCryptPasswordEncoder(8).encode(readPasswordFromUser);
    }

    @Benchmark
    public String bcryptWithSpringSecurity10() {
        // hash a password
        return new BCryptPasswordEncoder(10).encode(readPasswordFromUser);
    }

    @Benchmark
    public String bcryptWithSpringSecurity12() {
        // hash a password
        return new BCryptPasswordEncoder(12).encode(readPasswordFromUser);
    }

    @Benchmark
    public String scryptWithJhash() {
        return Hash.password(readPasswordFromUserChars).salt(salt).algorithm(Type.SCRYPT).create();
    }

    @Benchmark
    public String scryptWithPassword4j() {
        return Password.hash(readPasswordFromUserBytes).addSalt(salt).withScrypt().getResult();
    }

    @Benchmark
    public String scryptWithSpringSecurity() {
        // hash a password
        return SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8().encode(readPasswordFromUser);
    }

    @Benchmark
    public String pbkdf2() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // hash a password
        return new PBKDF2Password(salt).generatePassword(readPasswordFromUser);
    }

    @Benchmark
    public String pbkdf2Parameters() throws NoSuchAlgorithmException, InvalidKeySpecException, DecoderException {
        PBKDF2Password pbkdf2Password = new PBKDF2Password(PBKDF2Password.getSalt(PBKDF2_SALT_LENGTH), PBKDF2_ITERATIONS, PBKDF2_HASH_WIDTH, PBKDF2_ALGORITHM);
        // hash a password
        return pbkdf2Password.generatePassword(readPasswordFromUser);
    }

    @Benchmark
    public String pbkdf2WithJhash() throws InvalidHashException {
        return Hash.password(readPasswordFromUserChars).salt(salt).algorithm(Type.PBKDF2_SHA256).create();
    }

    @Benchmark
    public String pbkdf2WithPassword4j() {
        return Password.hash(readPasswordFromUserBytes).addSalt(salt).withPBKDF2().getResult();
    }

    @Benchmark
    public String pbkdf2WithSpringSecurity() {
        // hash a password
        return Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(readPasswordFromUser);
    }

    @Benchmark
    public String pbkdf2WithSpringSecurityParameters() {
        // Create instance
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder("", PBKDF2_SALT_LENGTH, PBKDF2_ITERATIONS, Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256);
        // hash a password
        return encoder.encode(readPasswordFromUser);
    }

    @Benchmark
    public String argon2() {
        String password;
        // Create instance
        Argon2 argon2 = Argon2Factory.create();
        // Read password from user
        try {
            // Hash password
            password = argon2.hash(10, 65536, 1, readPasswordFromUserBytes);
        } finally {
            // Wipe confidential data
            argon2.wipeArray(readPasswordFromUserBytes);
        }
        return password;
    }

    @Benchmark
    public String argon2WithHelper() {
        String password;
        // Create instance
        Argon2 argon2 = Argon2Factory.create();
        // Read password from user
        try {
            // find Iterations
            int iterations = Argon2Helper.findIterations(argon2, 1000, 65536, 1);
            // hash a password
            password = argon2.hash(iterations, 65536, 1, readPasswordFromUserBytes);
        } finally {
            // Wipe confidential data
            argon2.wipeArray(readPasswordFromUserBytes);
        }
        return password;
    }

    @Benchmark
    public String argon2WithPassword4j() {
        // hash
        return Password.hash(readPasswordFromUserBytes).addSalt(salt).withArgon2().getResult();
    }

    @Benchmark
    public String argon2WithSpringSecurity() {
        // hash a password
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(readPasswordFromUser);
    }
}
