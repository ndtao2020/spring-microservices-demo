package com.microservice.benchmark.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.amdelamar.jhash.Hash;
import com.amdelamar.jhash.algorithms.Type;
import com.kosprov.jargon2.api.Jargon2;
import com.kosprov.jargon2.internal.HasherImpl;
import com.kosprov.jargon2.nativeri.backend.NativeRiJargon2Backend;
import com.microservice.example.RandomUtils;
import com.microservice.example.crypto.PBKDF2Password;
import com.microservice.example.crypto.Sha512Hashing;
import com.password4j.Password;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Constants;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Helper;
import io.quarkus.elytron.security.common.BcryptUtil;
import org.openjdk.jmh.annotations.*;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class PasswordHashing {

    private static final int PBKDF2_SALT_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 310000;
    private static final int PBKDF2_HASH_WIDTH = 256; // SHA-256
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA" + PBKDF2_HASH_WIDTH; // SHA-256

    static byte[] salt = Sha512Hashing.getSalt();
    static String readPasswordFromUser = RandomUtils.generatePassword(20);
    static char[] readPasswordFromUserChars = readPasswordFromUser.toCharArray();
    static byte[] readPasswordFromUserBytes = readPasswordFromUser.getBytes(StandardCharsets.UTF_8);

    // ======================================================

    @Benchmark
    public String bcryptWithJhash() {
        return Hash.password(readPasswordFromUserChars).salt(salt).algorithm(Type.BCRYPT).create();
    }

    @Benchmark
    public String bcryptWithPassword4j() {
        return Password.hash(readPasswordFromUserBytes).withBcrypt().getResult();
    }

    @Benchmark
    public String bcryptWithFavrDev10() {
        // hash
        return BCrypt.withDefaults().hashToString(10, readPasswordFromUserChars);
    }

    @Benchmark
    public String mindrotJBCrypt10() {
        return org.mindrot.jbcrypt.BCrypt.hashpw(readPasswordFromUser, org.mindrot.jbcrypt.BCrypt.gensalt(10));
    }

    @Benchmark
    public String bcryptWithQuarkusSecurity10() {
        return BcryptUtil.bcryptHash(readPasswordFromUser, 10);
    }

    @Benchmark
    public String bcryptWithSpringSecurity10() {
        return new BCryptPasswordEncoder(10).encode(readPasswordFromUser);
    }

    // ======================================================

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

    // ======================================================

    @Benchmark
    public String pbkdf2() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // hash a password
        return new PBKDF2Password(salt).generatePassword(readPasswordFromUser);
    }

    @Benchmark
    public String pbkdf2Parameters() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBKDF2Password pbkdf2Password = new PBKDF2Password(PBKDF2Password.getSalt(PBKDF2_SALT_LENGTH), PBKDF2_ITERATIONS, PBKDF2_HASH_WIDTH, PBKDF2_ALGORITHM);
        // hash a password
        return pbkdf2Password.generatePassword(readPasswordFromUser);
    }

    @Benchmark
    public String pbkdf2WithJhash() {
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

    // ======================================================

    @Benchmark
    public String argon2() {
        return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH)
                .hash(2, 16, 1, readPasswordFromUserBytes);
    }

    @Benchmark
    public String argon2Parallelisms2() {
        return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH)
                .hash(2, 16, 2, readPasswordFromUserBytes);
    }

    @Benchmark
    public String argon2WithHelper() {
        // Create instance
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH);
        // hash a password
        return argon2.hash(Argon2Helper.findIterations(argon2, 1000, 65536, 1), 65536, 1, readPasswordFromUserBytes);
    }

    @Benchmark
    public String argon2WithJargon2() {
        Jargon2.Hasher hasher = new HasherImpl()
                .type(Jargon2.Type.ARGON2id)
                .memoryCost(65536)
                .parallelism(1)
                .saltLength(Argon2Constants.DEFAULT_SALT_LENGTH)
                .hashLength(Argon2Constants.DEFAULT_HASH_LENGTH);
        return hasher.password(readPasswordFromUserBytes).encodedHash();
    }

    @Benchmark
    public String argon2WithJargon2Parallelisms2() {
        Jargon2.Hasher hasher = new HasherImpl()
                .type(Jargon2.Type.ARGON2id)
                .memoryCost(65536)
                .parallelism(2)
                .saltLength(Argon2Constants.DEFAULT_SALT_LENGTH)
                .hashLength(Argon2Constants.DEFAULT_HASH_LENGTH);
        return hasher.password(readPasswordFromUserBytes).encodedHash();
    }

    @Benchmark
    public String argon2WithJargon2Native() {
        Jargon2.Hasher hasher = new HasherImpl()
                .backend(new NativeRiJargon2Backend())
                .type(Jargon2.Type.ARGON2id)
                .memoryCost(65536)
                .parallelism(1)
                .saltLength(Argon2Constants.DEFAULT_SALT_LENGTH)
                .hashLength(Argon2Constants.DEFAULT_HASH_LENGTH);
        return hasher.password(readPasswordFromUserBytes).encodedHash();
    }

    @Benchmark
    public String argon2WithJargon2NativeParallelisms2() {
        Jargon2.Hasher hasher = new HasherImpl()
                .backend(new NativeRiJargon2Backend())
                .type(Jargon2.Type.ARGON2id)
                .memoryCost(65536)
                .parallelism(2)
                .saltLength(Argon2Constants.DEFAULT_SALT_LENGTH)
                .hashLength(Argon2Constants.DEFAULT_HASH_LENGTH);
        return hasher.password(readPasswordFromUserBytes).encodedHash();
    }

    @Benchmark
    public String argon2WithPassword4j() {
        return Password.hash(readPasswordFromUserBytes).addSalt(salt).withArgon2().getResult();
    }

    @Benchmark
    public String argon2WithSpringSecurity() {
        Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder(Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH, 1, 16, 2);
        return passwordEncoder.encode(readPasswordFromUser);
    }

    @Benchmark
    public String argon2WithSpringSecurityParallelisms2() {
        Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder(Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH, 2, 16, 2);
        return passwordEncoder.encode(readPasswordFromUser);
    }
}
