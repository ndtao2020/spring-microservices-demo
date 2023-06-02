package com.microservice.example.codec;

import com.fasterxml.jackson.core.Base64Variants;
import com.google.common.io.BaseEncoding;
import com.microservice.example.RandomUtils;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.io.Encoders;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("Encode a String to Base64")
class Base64UrlEncodeTests {

    private static final String VALUE = RandomUtils.generateId(100);
    private static final byte[] VALUE_BYTES = VALUE.getBytes(StandardCharsets.UTF_8);
    private static final String BASE64_VALUE = Base64.getUrlEncoder().withoutPadding().encodeToString(VALUE_BYTES);

    @Test
    void java() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String encode = new String(encoder.encode(VALUE_BYTES), StandardCharsets.UTF_8);
        assertEquals(BASE64_VALUE, encode);
    }

    @Test
    void jboss() {
        String encode = org.jboss.resteasy.jose.jws.util.Base64Url.encode(VALUE_BYTES);
        assertEquals(BASE64_VALUE, encode);
    }

    @Test
    void nimbusdsJose() {
        com.nimbusds.jose.util.Base64URL base64 = com.nimbusds.jose.util.Base64URL.encode(VALUE_BYTES);
        assertEquals(BASE64_VALUE, base64.toString());
    }

    @Test
    void jose4jInternalCommonsCodec() {
        String encode = org.jose4j.base64url.internal.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(VALUE_BYTES);
        assertEquals(BASE64_VALUE, encode);
    }

    @Test
    void apacheCommonsCodec() {
        String encode = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(VALUE_BYTES);
        assertEquals(BASE64_VALUE, encode);
    }

    @Test
    void jackson() {
        String encode = Base64Variants.MODIFIED_FOR_URL.encode(VALUE_BYTES);
        assertEquals(BASE64_VALUE, encode);
    }

    @Test
    void guavaGoogle() {
        String encode = BaseEncoding.base64Url().omitPadding().encode(VALUE_BYTES);
        assertEquals(BASE64_VALUE, encode);
    }

    @Test
    void jsonWebToken() {
        Encoder<byte[], String> base64UrlEncoder = Encoders.BASE64URL;
        String encode = base64UrlEncoder.encode(VALUE_BYTES);
        assertEquals(BASE64_VALUE, encode);
    }
}
