package com.microservice.example.crypto;

import com.microservice.example.RandomUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("Test AesAlgorithm")
class AesAlgorithmTests {

    @Test
    void testAesAlgorithm() throws InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeySpecException, InvalidKeyException {

        String saltKey = RandomUtils.generatePassword(50);
        String text = RandomUtils.generatePassword(50);

        System.out.println("saltKey: " + saltKey);
        System.out.println("text: " + text);

        String encryptString = AesAlgorithm.encrypt(text, saltKey);
        String decryptString = AesAlgorithm.decrypt(encryptString, saltKey);

        System.out.println("encryptString: " + encryptString);
        System.out.println("decryptString: " + decryptString);

        assertEquals(decryptString, text);
    }
}
