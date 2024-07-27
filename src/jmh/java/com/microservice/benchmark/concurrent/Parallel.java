package com.microservice.benchmark.concurrent;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class Parallel {

  private static final long millis = 10;
  private final int processors = Runtime.getRuntime().availableProcessors();

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(Parallel.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }

  @Benchmark
  public void processSerially() {
    for (int i = 0; i < 100; i++) {
      try {
        Thread.sleep(millis);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }

  @Benchmark
  public void executorService() {
    ExecutorService executorService = Executors.newFixedThreadPool(processors);
    List<CompletableFuture<Void>> futures = new ArrayList<>();
    for (int i = 0; i < 100; i++) {
      CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
        try {
          Thread.sleep(millis);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }, executorService);
      futures.add(future);
    }
    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    executorService.shutdown();
  }

  @Benchmark
  public void executorVirtualThread() {
    ExecutorService executorService = Executors.newVirtualThreadPerTaskExecutor();
    List<CompletableFuture<Void>> futures = new ArrayList<>();
    for (int i = 0; i < 100; i++) {
      CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
        try {
          Thread.sleep(millis);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }, executorService);
      futures.add(future);
    }
    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    executorService.shutdown();
  }

  @Benchmark
  public void executorWorkStealingPool() {
    ExecutorService executorService = Executors.newWorkStealingPool();
    List<CompletableFuture<Void>> futures = new ArrayList<>();
    for (int i = 0; i < 100; i++) {
      CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
        try {
          Thread.sleep(millis);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }, executorService);
      futures.add(future);
    }
    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    executorService.shutdown();
  }

  @Benchmark
  public void executorCachedThreadPool() {
    ExecutorService executorService = Executors.newCachedThreadPool();
    List<CompletableFuture<Void>> futures = new ArrayList<>();
    for (int i = 0; i < 100; i++) {
      CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
        try {
          Thread.sleep(millis);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }, executorService);
      futures.add(future);
    }
    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    executorService.shutdown();
  }

  @Benchmark
  public void completableFuture() {
    List<CompletableFuture<Void>> futures = new ArrayList<>();
    for (int i = 0; i < 100; i++) {
      CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
        try {
          Thread.sleep(millis);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      });
      futures.add(future);
    }
    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
  }

  @Benchmark
  public void stream() {
    IntStream.range(0, 100)
        .parallel()
        .forEach(i -> {
          try {
            Thread.sleep(millis);
          } catch (InterruptedException e) {
            e.printStackTrace();
          }
        });
  }

  @Benchmark
  public void streamSupport() {
    Iterable<Integer> iterable = () -> IntStream.range(0, 100).iterator();
    Stream<Integer> stream = StreamSupport.stream(iterable.spliterator(), true);
    stream.forEach(i -> {
      try {
        Thread.sleep(millis);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    });
  }
}
