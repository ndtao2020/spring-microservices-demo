package com.microservice.benchmark;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class FinalKeyword {

    public static void main(String[] args) throws Exception {
        org.openjdk.jmh.Main.main(args);
    }

    @Benchmark
    public static String concatNonFinalStrings() {
        String x = "x";
        String y = "y";
        return x + y;
    }

    @Benchmark
    public static String concatFinalStrings() {
        final String x = "x";
        final String y = "y";
        return x + y;
    }
}
