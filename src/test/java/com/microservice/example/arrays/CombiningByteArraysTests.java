package com.microservice.example.arrays;

import com.google.common.primitives.Bytes;
import com.microservice.example.RandomUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.random.RandomGenerator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@DisplayName("Combining More Byte Arrays")
class CombiningByteArraysTests {

    static final int min = 5;
    static final int max = 50;

    static byte[] first = new byte[RandomUtils.generateInt(min, max)];
    static byte[] second = new byte[RandomUtils.generateInt(min, max)];
    static byte[] third = new byte[RandomUtils.generateInt(min, max)];
    static byte[] fourth = new byte[RandomUtils.generateInt(min, max)];
    static byte[] expectedArray = new byte[first.length + second.length + third.length + fourth.length];

    @BeforeAll
    static void initAll() {
        RandomGenerator m = RandomGenerator.getDefault();
        // random
        m.nextBytes(first);
        m.nextBytes(second);
        m.nextBytes(third);
        m.nextBytes(fourth);
        // copy
        System.arraycopy(first, 0, expectedArray, 0, first.length);
        System.arraycopy(second, 0, expectedArray, first.length, second.length);
        System.arraycopy(third, 0, expectedArray, first.length + second.length, third.length);
        System.arraycopy(fourth, 0, expectedArray, first.length + second.length + third.length, fourth.length);
    }

    @Test
    void plainJava() {
        byte[] combined = new byte[first.length + second.length + third.length + fourth.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, 0 + first.length, second.length);
        for (int i = 0; i < third.length; i++) {
            combined[i + first.length + second.length] = third[i];
        }
        for (int i = 0; i < fourth.length; i++) {
            combined[i + first.length + second.length + third.length] = fourth[i];
        }
        // assert
        assertArrayEquals(expectedArray, combined);
    }

    @Test
    void systemArrayCopy() {
        byte[] combined = new byte[first.length + second.length + third.length + fourth.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        System.arraycopy(third, 0, combined, first.length + second.length, third.length);
        System.arraycopy(fourth, 0, combined, first.length + second.length + third.length, fourth.length);
        // assert
        assertArrayEquals(expectedArray, combined);
    }

    @Test
    void byteBuffer() {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[first.length + second.length + third.length + fourth.length]);
        buffer.put(first);
        buffer.put(second);
        buffer.put(third);
        buffer.put(fourth);
        // assert
        assertArrayEquals(expectedArray, buffer.array());
    }

    @Test
    void byteArrayOutputStream() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(first, 0, first.length);
        outputStream.write(second, 0, second.length);
        outputStream.write(third, 0, third.length);
        outputStream.write(fourth, 0, fourth.length);
        // assert
        assertArrayEquals(expectedArray, outputStream.toByteArray());
    }

    @Test
    void guava() {
        // assert
        assertArrayEquals(expectedArray, Bytes.concat(first, second, third, fourth));
    }

    @Test
    void apacheCommons() {
        byte[] combined1 = ArrayUtils.addAll(first, second);
        byte[] combined2 = ArrayUtils.addAll(third, fourth);
        // assert
        assertArrayEquals(expectedArray, ArrayUtils.addAll(combined1, combined2));
    }
}
