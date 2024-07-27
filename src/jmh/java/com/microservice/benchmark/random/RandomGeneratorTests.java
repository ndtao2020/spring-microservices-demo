package com.microservice.benchmark.random;

import com.microservice.example.RandomUtils;
import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;
import java.util.random.RandomGenerator;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class RandomGeneratorTests {

  private static final char[] SUBSET = RandomUtils.R_O_U_CHAR;
  private static final int LENGTH = 6;

  @Benchmark
  public String testRandom() {
    RandomGenerator generator = RandomGenerator.of("Random");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testSecureRandom() {
    RandomGenerator generator = RandomGenerator.of("SecureRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testSplittableRandom() {
    RandomGenerator generator = RandomGenerator.of("SplittableRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testL128X1024MixRandom() {
    RandomGenerator generator = RandomGenerator.of("L128X1024MixRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testL128X128MixRandom() {
    RandomGenerator generator = RandomGenerator.of("L128X128MixRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testL128X256MixRandom() {
    RandomGenerator generator = RandomGenerator.of("L128X256MixRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testL32X64MixRandom() {
    RandomGenerator generator = RandomGenerator.of("L32X64MixRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testL64X1024MixRandom() {
    RandomGenerator generator = RandomGenerator.of("L64X1024MixRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testL64X128MixRandom() {
    RandomGenerator generator = RandomGenerator.of("L64X128MixRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testL64X128StarStarRandom() {
    RandomGenerator generator = RandomGenerator.of("L64X128StarStarRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testL64X256MixRandom() {
    RandomGenerator generator = RandomGenerator.of("L64X256MixRandom");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testXoroshiro128PlusPlus() {
    RandomGenerator generator = RandomGenerator.of("Xoroshiro128PlusPlus");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }

  @Benchmark
  public String testXoshiro256PlusPlus() {
    RandomGenerator generator = RandomGenerator.of("Xoshiro256PlusPlus");
    char[] buf = new char[LENGTH];
    for (int i = 0; i < buf.length; i++) {
      buf[i] = SUBSET[generator.nextInt(SUBSET.length)];
    }
    return new String(buf);
  }
}
