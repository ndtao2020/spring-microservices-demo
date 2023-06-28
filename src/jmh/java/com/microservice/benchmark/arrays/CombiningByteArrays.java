package com.microservice.benchmark.arrays;

import com.microservice.example.RandomUtils;
import org.openjdk.jmh.annotations.*;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.random.RandomGenerator;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class CombiningByteArrays {

    @Param({"10", "100"})
    public int max;

    private final byte[] first = new byte[RandomUtils.generateInt(5, max)];
    private final byte[] second = new byte[RandomUtils.generateInt(5, max)];
    private final byte[] third = new byte[RandomUtils.generateInt(5, max)];
    private final byte[] fourth = new byte[RandomUtils.generateInt(5, max)];

    @Setup
    public void setup() {
        final RandomGenerator m = RandomGenerator.getDefault();
        // random
        m.nextBytes(first);
        m.nextBytes(second);
        m.nextBytes(third);
        m.nextBytes(fourth);
    }

    @Benchmark
    public byte[] plainJava() {
        final byte[] combined = new byte[first.length + second.length + third.length + fourth.length];
        for (int i = 0; i < first.length; i++) {
            combined[i] = first[i];
        }
        for (int i = 0; i < second.length; i++) {
            combined[i + first.length] = second[i];
        }
        for (int i = 0; i < third.length; i++) {
            combined[i + first.length + second.length] = third[i];
        }
        for (int i = 0; i < fourth.length; i++) {
            combined[i + first.length + second.length + third.length] = fourth[i];
        }
        return combined;
    }

    @Benchmark
    public byte[] systemArrayCopy() {
        final byte[] combined = new byte[first.length + second.length + third.length + fourth.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        System.arraycopy(third, 0, combined, first.length + second.length, third.length);
        System.arraycopy(fourth, 0, combined, first.length + second.length + third.length, fourth.length);
        return combined;
    }

    @Benchmark
    public byte[] byteBuffer() {
        final ByteBuffer buff = ByteBuffer.wrap(new byte[first.length + second.length + third.length + fourth.length]);
        buff.put(first);
        buff.put(second);
        buff.put(third);
        buff.put(fourth);
        return buff.array();
    }

    @Benchmark
    public byte[] byteArrayOutputStream() {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(first, 0, first.length);
        out.write(second, 0, second.length);
        out.write(third, 0, third.length);
        out.write(fourth, 0, fourth.length);
        return out.toByteArray();
    }
}
