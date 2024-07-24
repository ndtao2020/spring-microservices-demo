package com.microservice.benchmark.codec;

import com.fasterxml.jackson.core.Base64Variants;
import com.google.common.io.BaseEncoding;
import com.microservice.example.RandomUtils;
import io.jsonwebtoken.io.Encoders;
import org.apache.logging.log4j.util.Base64Util;
import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class Base64EncodeTests {

  private static final String VALUE = RandomUtils.generateId(100);
  private static final byte[] VALUE_BYTES = VALUE.getBytes(StandardCharsets.UTF_8);

  @Benchmark
  public String java() {
    return new String(Base64.getEncoder().encode(VALUE_BYTES), StandardCharsets.UTF_8);
  }

  @Benchmark
  public String jboss() {
    return org.jboss.resteasy.jose.jws.util.Base64.encodeBytes(VALUE_BYTES);
  }

  @Benchmark
  public String kotlin() {
    return kotlin.io.encoding.Base64.Default.encode(VALUE_BYTES, 0, VALUE_BYTES.length);
  }

  @Benchmark
  public String nimbusdsJose() {
    return com.nimbusds.jose.util.Base64.encode(VALUE_BYTES).toString();
  }

  @Benchmark
  public String bouncyCastlejdk18on() {
    return org.bouncycastle.util.encoders.Base64.toBase64String(VALUE_BYTES);
  }

  @Benchmark
  public String jose4jInternalCommonsCodec() {
    return org.jose4j.base64url.internal.apache.commons.codec.binary.Base64.encodeBase64String(VALUE_BYTES);
  }

  @Benchmark
  public String apacheCommonsCodec() {
    return org.apache.commons.codec.binary.Base64.encodeBase64String(VALUE_BYTES);
  }

  @Benchmark
  public String apacheLog4j() {
    return Base64Util.encode(VALUE);
  }

  @Benchmark
  public String jackson() {
    return Base64Variants.getDefaultVariant().encode(VALUE_BYTES);
  }

  @Benchmark
  public String guavaGoogle() {
    return BaseEncoding.base64().encode(VALUE_BYTES);
  }

  @Benchmark
  public String jsonWebToken() {
    return Encoders.BASE64.encode(VALUE_BYTES);
  }
}
