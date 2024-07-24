package com.microservice.benchmark.codec;

import com.fasterxml.jackson.core.Base64Variants;
import com.google.common.io.BaseEncoding;
import com.microservice.example.RandomUtils;
import io.jsonwebtoken.io.Decoders;
import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class Base64UrlDecodeTests {

  private static final String BASE64_VALUE = Base64.getUrlEncoder().withoutPadding()
      .encodeToString(RandomUtils.generateId(100).getBytes(StandardCharsets.UTF_8));
  private static final byte[] BASE64_BYTES = BASE64_VALUE.getBytes(StandardCharsets.UTF_8);

  @Benchmark
  public byte[] java() {
    return Base64.getUrlDecoder().decode(BASE64_BYTES);
  }

  @Benchmark
  public byte[] jboss() {
    return org.jboss.resteasy.jose.jws.util.Base64Url.decode(BASE64_VALUE);
  }

  @Benchmark
  public byte[] nimbusdsJose() {
    return com.nimbusds.jose.util.Base64URL.from(BASE64_VALUE).decode();
  }

  @Benchmark
  public byte[] jose4jInternalCommonsCodec() {
    return org.jose4j.base64url.internal.apache.commons.codec.binary.Base64.decodeBase64(BASE64_BYTES);
  }

  @Benchmark
  public byte[] apacheCommonsCodec() {
    return org.apache.commons.codec.binary.Base64.decodeBase64(BASE64_BYTES);
  }

  @Benchmark
  public byte[] jackson() {
    return Base64Variants.MODIFIED_FOR_URL.decode(BASE64_VALUE);
  }

  @Benchmark
  public byte[] guavaGoogle() {
    return BaseEncoding.base64Url().decode(BASE64_VALUE);
  }

  @Benchmark
  public byte[] jsonWebToken() {
    return Decoders.BASE64URL.decode(BASE64_VALUE);
  }
}
