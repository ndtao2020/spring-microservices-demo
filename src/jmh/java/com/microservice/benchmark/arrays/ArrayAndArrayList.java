package com.microservice.benchmark.arrays;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class ArrayAndArrayList {

    protected Integer[] array = Collections.nCopies(256, 1).toArray(new Integer[0]);
    protected final List<Integer> list = new ArrayList<>(Arrays.asList(array));

    @Benchmark
    public Integer[] arrayCreation() {
        return new Integer[256];
    }

    @Benchmark
    public List<Integer> arrayListCreation() {
        return new ArrayList<>(256);
    }

    @Benchmark
    public Integer[] arrayItemsSetting() {
        for (int i = 0; i < 256; i++) {
            array[i] = i;
        }
        return array;
    }

    @Benchmark
    public List<Integer> arrayListItemsSetting() {
        for (int i = 0; i < 256; i++) {
            list.set(i, i);
        }
        return list;
    }

    @Benchmark
    public void arrayItemsRetrieval(Blackhole blackhole) {
        for (int i = 0; i < 256; i++) {
            blackhole.consume(array[i]);
        }
    }

    @Benchmark
    public void arrayListItemsRetrieval(Blackhole blackhole) {
        for (int i = 0; i < 256; i++) {
            blackhole.consume(list.get(i));
        }
    }

    @Benchmark
    public void arrayCloning(Blackhole blackhole) {
        blackhole.consume(array.clone());
    }

    @Benchmark
    public void arrayListCloning(Blackhole blackhole) {
        blackhole.consume(new ArrayList<>(list));
    }
}
