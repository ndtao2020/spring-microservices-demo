package com.microservice.benchmark.arrays;

import org.openjdk.jmh.annotations.*;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@BenchmarkMode(Mode.AverageTime)
@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class PrimitivesCopy {

  @Param({"10", "1000000"})
  public int size;

  int[] src;

  @Setup
  public void setup() throws NoSuchAlgorithmException {
    Random r = SecureRandom.getInstanceStrong();
    src = new int[size];
    for (int i = 0; i < size; i++) {
      src[i] = r.nextInt();
    }
  }

  @Benchmark
  public int[] systemArrayCopyBenchmark() {
    int[] target = new int[size];
    System.arraycopy(src, 0, target, 0, size);
    return target;
  }

  @Benchmark
  public int[] arraysCopyOfBenchmark() {
    return Arrays.copyOf(src, size);
  }
}
