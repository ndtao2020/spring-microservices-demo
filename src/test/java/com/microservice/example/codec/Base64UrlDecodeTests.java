package com.microservice.example.codec;

import com.fasterxml.jackson.core.Base64Variants;
import com.google.common.io.BaseEncoding;
import com.microservice.example.RandomUtils;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@DisplayName("Encode a String to Base64")
class Base64UrlDecodeTests {

    private static final String BASE64_VALUE = Base64.getUrlEncoder().withoutPadding().encodeToString(RandomUtils.generateId(100).getBytes(StandardCharsets.UTF_8));
    private static final byte[] BASE64_BYTES = BASE64_VALUE.getBytes(StandardCharsets.UTF_8);

    private static final byte[] BASE64_DECODE_BYTES = Base64.getUrlDecoder().decode(BASE64_BYTES);

    @Test
    void java() {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        byte[] bytes = decoder.decode(BASE64_BYTES);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void jboss() {
        byte[] bytes = org.jboss.resteasy.jose.jws.util.Base64Url.decode(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void nimbusdsJose() {
        com.nimbusds.jose.util.Base64URL base64 = com.nimbusds.jose.util.Base64URL.from(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, base64.decode());
    }

    @Test
    void jose4jInternalCommonsCodec() {
        byte[] bytes = org.jose4j.base64url.internal.apache.commons.codec.binary.Base64.decodeBase64(BASE64_BYTES);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void apacheCommonsCodec() {
        byte[] bytes = org.apache.commons.codec.binary.Base64.decodeBase64(BASE64_BYTES);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void jackson() {
        byte[] bytes = Base64Variants.MODIFIED_FOR_URL.decode(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void guavaGoogle() {
        byte[] bytes = BaseEncoding.base64Url().decode(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void jsonWebToken() {
        Decoder<CharSequence, byte[]> base64UrlDecoder = Decoders.BASE64URL;
        byte[] bytes = base64UrlDecoder.decode(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }
}
