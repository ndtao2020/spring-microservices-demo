package com.microservice.benchmark.codec;

import com.fasterxml.jackson.core.Base64Variants;
import com.google.common.io.BaseEncoding;
import com.microservice.example.RandomUtils;
import io.jsonwebtoken.io.Decoders;
import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class Base64DecodeTests {

  private static final String BASE64_VALUE = Base64.getEncoder()
      .encodeToString(RandomUtils.generateId(100).getBytes(StandardCharsets.UTF_8));
  private static final byte[] BASE64_BYTES = BASE64_VALUE.getBytes(StandardCharsets.UTF_8);

  @Benchmark
  public byte[] java() {
    return Base64.getDecoder().decode(BASE64_BYTES);
  }

  @Benchmark
  public byte[] jboss() throws IOException {
    return org.jboss.resteasy.jose.jws.util.Base64.decode(BASE64_VALUE);
  }

  @Benchmark
  public byte[] kotlin() {
    return kotlin.io.encoding.Base64.Default.decode(BASE64_BYTES, 0, BASE64_BYTES.length);
  }

  @Benchmark
  public byte[] nimbusdsJose() {
    return com.nimbusds.jose.util.Base64.from(BASE64_VALUE).decode();
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
    return Base64Variants.getDefaultVariant().decode(BASE64_VALUE);
  }

  @Benchmark
  public byte[] guavaGoogle() {
    return BaseEncoding.base64().decode(BASE64_VALUE);
  }

  @Benchmark
  public byte[] jsonWebToken() {
    return Decoders.BASE64.decode(BASE64_VALUE);
  }
}
