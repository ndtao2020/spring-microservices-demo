package com.microservice.example.jwt.rsa;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;

public class RSAUtil {
    public KeyPair getKeyPair(String path, String password, String alias) {
        try (InputStream is = new FileInputStream(path)) {
            char[] pass = password.toCharArray();
            KeyStore store = KeyStore.getInstance("JKS");
            store.load(is, pass);
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) store.getKey(alias, pass);
            return new KeyPair(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent())), key);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot load keys from store: " + path, e);
        }
    }
}
