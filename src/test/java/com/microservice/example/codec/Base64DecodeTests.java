package com.microservice.example.codec;

import com.fasterxml.jackson.core.Base64Variants;
import com.google.common.io.BaseEncoding;
import com.microservice.example.RandomUtils;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@DisplayName("Encode a String to Base64")
class Base64DecodeTests {

    private static final String BASE64_VALUE = Base64.getEncoder().encodeToString(RandomUtils.generateId(100).getBytes(StandardCharsets.UTF_8));
    private static final byte[] BASE64_BYTES = BASE64_VALUE.getBytes(StandardCharsets.UTF_8);
    private static final byte[] BASE64_DECODE_BYTES = Base64.getDecoder().decode(BASE64_BYTES);

    @Test
    void java() {
        byte[] bytes = Base64.getDecoder().decode(BASE64_BYTES);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void jboss() throws IOException {
        byte[] bytes = org.jboss.resteasy.jose.jws.util.Base64.decode(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void kotlin() {
        byte[] bytes = kotlin.io.encoding.Base64.Default.decode(BASE64_BYTES, 0, BASE64_BYTES.length);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void nimbusdsJose() {
        com.nimbusds.jose.util.Base64 base64 = com.nimbusds.jose.util.Base64.from(BASE64_VALUE);
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
        byte[] bytes = Base64Variants.getDefaultVariant().decode(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void guavaGoogle() {
        byte[] bytes = BaseEncoding.base64().decode(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }

    @Test
    void jsonWebToken() {
        Decoder<CharSequence, byte[]> base64Decoder = Decoders.BASE64;
        byte[] bytes = base64Decoder.decode(BASE64_VALUE);
        assertArrayEquals(BASE64_DECODE_BYTES, bytes);
    }
}
