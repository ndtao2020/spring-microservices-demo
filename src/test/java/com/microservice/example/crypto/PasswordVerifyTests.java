package com.microservice.example.crypto;

import at.favre.lib.crypto.bcrypt.BCrypt;
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

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Verify a Password")
class PasswordVerifyTests {

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

//    @Test
//    void scryptWithJhash() throws InvalidHashException {
//        assertTrue(Hash.password(readPasswordFromUserChars).salt(saltBytes).algorithm(Type.SCRYPT).verify(SCRYPT_PASSWORD));
//    }

    @Test
    void scryptWithPassword4j() {
        assertTrue(Password.check(readPasswordFromUserBytes, SCRYPT_PASSWORD_BYTES).addSalt(saltBytes).withScrypt());
    }

//    @Test
//    void scryptWithSpringSecurity() {
//        // hash a password
//        assertTrue(SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8().matches(readPasswordFromUser, SCRYPT_PASSWORD));
//    }

    // ======================================================

//    @Test
//    void pbkdf2WithJhash() throws InvalidHashException {
//        assertTrue(Hash.password(readPasswordFromUserChars).salt(saltBytes).algorithm(Type.PBKDF2_SHA256).verify(PBKDF2_PASSWORD));
//    }
//
//    @Test
//    void pbkdf2WithPassword4j() {
//        assertTrue(Password.check(readPasswordFromUserBytes, PBKDF2_PASSWORD_BYTES).addSalt(saltBytes).withPBKDF2());
//    }

    @Test
    void pbkdf2WithSpringSecurity() {
        // hash a password
        assertTrue(new Pbkdf2PasswordEncoder("", 16, 310000, Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256)
                .matches(readPasswordFromUser, PBKDF2_PASSWORD));
    }

    // ======================================================

    @Test
    void argon2() {
        Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH);
        assertTrue(argon2.verify(ARGON2_PASSWORD, readPasswordFromUserBytes));
    }

    @Test
    void argon2WithSpringSecurity() {
        Argon2PasswordEncoder passwordEncoder = new Argon2PasswordEncoder(Argon2Constants.DEFAULT_SALT_LENGTH, Argon2Constants.DEFAULT_HASH_LENGTH, 1, 16, 2);
        // hash a password
        assertTrue(passwordEncoder.matches(readPasswordFromUser, ARGON2_PASSWORD));
    }
}
