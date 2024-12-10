package com.microservice.benchmark.hashing;

import com.dynatrace.hash4j.hashing.Hasher64;
import com.dynatrace.hash4j.hashing.Hashing;
import com.microservice.example.RandomUtils;
import net.jpountz.xxhash.XXHash32;
import net.jpountz.xxhash.XXHash64;
import net.jpountz.xxhash.XXHashFactory;
import net.openhft.hashing.LongHashFunction;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.concurrent.TimeUnit;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.CRC32C;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class HashingFunction {

  private static final String message = RandomUtils.generateId(100);

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(HashingFunction.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }

  private byte[] messageBytes;
  private Adler32 adler32;
  private CRC32C crc32C;

  private XXHash32 xxHash32;
  private XXHash64 xxHash64;
  private Hasher64 hasher64;
  private LongHashFunction xx3b64;

  @Setup
  public void setup() {
    messageBytes = message.getBytes(StandardCharsets.UTF_8);

    adler32 = new Adler32();
    crc32C = new CRC32C();

    XXHashFactory xxHashFactory = XXHashFactory.fastestInstance();
    xxHash32 = xxHashFactory.hash32();
    xxHash64 = xxHashFactory.hash64();
    hasher64 = Hashing.xxh3_64();
    xx3b64 = LongHashFunction.xx3();
  }

  @Benchmark
  public String adler32() {
    adler32.update(messageBytes);
    return Long.toHexString(adler32.getValue());
  }

  @Benchmark
  public String cr32c() {
    crc32C.update(messageBytes);
    return Long.toHexString(crc32C.getValue());
  }

  @Benchmark
  public String md5() throws NoSuchAlgorithmException {
    // Create MessageDigest instance for MD5
    MessageDigest md = MessageDigest.getInstance("MD5");
    // Add password bytes to digest
    md.update(messageBytes);
    // Convert it to hexadecimal format
    StringBuilder sb = new StringBuilder();
    for (byte b : md.digest()) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  @Benchmark
  public String xxh32() {
    return Long.toHexString(xxHash32.hash(messageBytes, 0, messageBytes.length, 0));
  }

  @Benchmark
  public String xxh64() {
    return Long.toHexString(xxHash64.hash(messageBytes, 0, messageBytes.length, 0));
  }

  @Benchmark
  public String xxh3_jhash4() {
    return Long.toHexString(hasher64.hashBytesToLong(messageBytes, 0, messageBytes.length));
  }

  @Benchmark
  public String xxh3_zero_allocation() {
    return Long.toHexString(xx3b64.hashBytes(messageBytes, 0, messageBytes.length));
  }
}
