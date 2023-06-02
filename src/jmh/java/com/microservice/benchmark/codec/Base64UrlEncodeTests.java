package com.microservice.benchmark.codec;

import com.fasterxml.jackson.core.Base64Variants;
import com.google.common.io.BaseEncoding;
import com.microservice.example.RandomUtils;
import io.jsonwebtoken.io.Encoders;
import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class Base64UrlEncodeTests {

    private static final String VALUE = RandomUtils.generateId(100);
    private static final byte[] VALUE_BYTES = VALUE.getBytes(StandardCharsets.UTF_8);

    @Benchmark
    public byte[] javaToByte() {
        return Base64.getUrlEncoder().withoutPadding().encode(VALUE_BYTES);
    }

    @Benchmark
    public String java() {
        return new String(Base64.getUrlEncoder().withoutPadding().encode(VALUE_BYTES), StandardCharsets.UTF_8);
    }

    @Benchmark
    public String jboss() {
        return org.jboss.resteasy.jose.jws.util.Base64Url.encode(VALUE_BYTES);
    }

    @Benchmark
    public String nimbusdsJose() {
        return com.nimbusds.jose.util.Base64URL.encode(VALUE_BYTES).toString();
    }

    @Benchmark
    public byte[] jose4jInternalCommonsCodecToByte() {
        return org.jose4j.base64url.internal.apache.commons.codec.binary.Base64.encodeBase64URLSafe(VALUE_BYTES);
    }

    @Benchmark
    public String jose4jInternalCommonsCodec() {
        return org.jose4j.base64url.internal.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(VALUE_BYTES);
    }

    @Benchmark
    public byte[] apacheCommonsCodecToByte() {
        return org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(VALUE_BYTES);
    }

    @Benchmark
    public String apacheCommonsCodec() {
        return org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(VALUE_BYTES);
    }

    @Benchmark
    public String jackson() {
        return Base64Variants.MODIFIED_FOR_URL.encode(VALUE_BYTES);
    }

    @Benchmark
    public String guavaGoogle() {
        return BaseEncoding.base64Url().omitPadding().encode(VALUE_BYTES);
    }

    @Benchmark
    public String jsonWebToken() {
        return Encoders.BASE64URL.encode(VALUE_BYTES);
    }
}
