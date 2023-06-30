package com.microservice.benchmark;

import org.openjdk.jmh.annotations.*;

import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class FinalKeyword {

    public static final char DELIMITER = '.';
    protected static final byte[] DELIMITER_BYTES = {(byte) 46};
    private static final byte[] TOKEN_HEADER = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9".getBytes(UTF_8);
    private static final byte[] TOKEN_PAYLOAD = "eyJqdGkiOiJjdlYzYkdPODZmZFBGbzFTVzRLNSIsImlzcyI6Imh0dHBzOi8vdGFvcW4ucGFnZXMuZGV2Iiwic3ViIjoibmR0YW8yMDIwIiwiZXhwIjoxNjg4MDkyNDA2fQ".getBytes(UTF_8);
    private static final byte[] TOKEN_SIGNATURE = "srLLlqcl_9T3cuM007J3ROl9oRRBgo04BHASQ_W5g7wgfbYhkcAfV7tV9mjy6Za6jhZt-Nk-xw3IQJWIaK1ak8koODTUDUpClNFUltLeZPrUgnQSl5iap8AnOvpykWXN__iGn-r-FBZe_1Xk929mnAOBexMbaIXukluWa_taCn_jQGezo9A915TaJRgxde57LRltmKC6mq3HzqFHNLQ7fxcwwj_Eu7rbWG86BOwbz5o6BoWRmzckFVOyW3IJsiLd1uHXrIkwiytscPQLIKYmw4w8gBlt_c0vMO7jnF-Q3dxns6n240PNPt5AZ2SvHzweqtFd-YF3UJ8wwf9Vy-29eg".getBytes(UTF_8);
    private static final String TOKEN = new String(TOKEN_HEADER, UTF_8) + DELIMITER + new String(TOKEN_PAYLOAD, UTF_8) + DELIMITER + new String(TOKEN_SIGNATURE, UTF_8);

    @Benchmark
    public int indexOfWithChar() {
        return TOKEN.indexOf('.');
    }

    @Benchmark
    public int indexOfWithString() {
        return TOKEN.indexOf(".");
    }

    @Benchmark
    public String concatenateStrings() {
        return new String(TOKEN_HEADER, UTF_8) + DELIMITER + new String(TOKEN_PAYLOAD, UTF_8) + DELIMITER + new String(TOKEN_SIGNATURE, UTF_8);
    }

    @Benchmark
    public String concatenateStringsStringBuilder() {
        StringBuilder builder = new StringBuilder();
        builder.append(new String(TOKEN_HEADER, UTF_8));
        builder.append(DELIMITER);
        builder.append(new String(TOKEN_PAYLOAD, UTF_8));
        builder.append(DELIMITER);
        builder.append(new String(TOKEN_SIGNATURE, UTF_8));
        return builder.toString();
    }

//    @Benchmark
//    public byte[] plainJava() {
//        byte[] bytes = new byte[TOKEN_HEADER.length + DELIMITER_BYTES.length + TOKEN_PAYLOAD.length + DELIMITER_BYTES.length + TOKEN_SIGNATURE.length];
//        // for loop
//        for (int i = 0; i < TOKEN_HEADER.length + 1; i++) {
//            bytes[i] = TOKEN_HEADER[i];
//        }
//        bytes[TOKEN_HEADER.length] = DELIMITER_BYTES[0];
//        for (int i = 0; i < TOKEN_PAYLOAD.length; i++) {
//            bytes[i + TOKEN_HEADER.length + DELIMITER_BYTES.length] = TOKEN_PAYLOAD[i];
//        }
//        bytes[TOKEN_HEADER.length + DELIMITER_BYTES.length + TOKEN_PAYLOAD.length] = DELIMITER_BYTES[0];
//        for (int i = 0; i < TOKEN_SIGNATURE.length; i++) {
//            bytes[i + TOKEN_HEADER.length + DELIMITER_BYTES.length + TOKEN_PAYLOAD.length + DELIMITER_BYTES.length] = TOKEN_SIGNATURE[i];
//        }
//        return bytes;
//    }

    @Benchmark
    public String concatenateStringsArrays() {
        // init new array
        byte[] bytes = new byte[TOKEN_HEADER.length + DELIMITER_BYTES.length + TOKEN_PAYLOAD.length + DELIMITER_BYTES.length + TOKEN_SIGNATURE.length];
        // copy new array
        System.arraycopy(TOKEN_HEADER, 0, bytes, 0, TOKEN_HEADER.length);
        System.arraycopy(DELIMITER_BYTES, 0, bytes, TOKEN_HEADER.length, DELIMITER_BYTES.length);
        System.arraycopy(TOKEN_PAYLOAD, 0, bytes, TOKEN_HEADER.length + DELIMITER_BYTES.length, TOKEN_PAYLOAD.length);
        System.arraycopy(DELIMITER_BYTES, 0, bytes, TOKEN_HEADER.length + DELIMITER_BYTES.length + TOKEN_PAYLOAD.length, DELIMITER_BYTES.length);
        System.arraycopy(TOKEN_SIGNATURE, 0, bytes, TOKEN_HEADER.length + DELIMITER_BYTES.length + TOKEN_PAYLOAD.length + DELIMITER_BYTES.length, TOKEN_SIGNATURE.length);
        // return token
        return new String(bytes, UTF_8);
    }

    @Benchmark
    public String concatenateStringsByteBufferWrap() {
        // init new array
        final ByteBuffer buff = ByteBuffer.wrap(new byte[TOKEN_HEADER.length + DELIMITER_BYTES.length + TOKEN_PAYLOAD.length + DELIMITER_BYTES.length + TOKEN_SIGNATURE.length]);
        buff.put(TOKEN_HEADER);
        buff.put(DELIMITER_BYTES);
        buff.put(TOKEN_PAYLOAD);
        buff.put(DELIMITER_BYTES);
        buff.put(TOKEN_SIGNATURE);
        // return token
        return new String(buff.array(), UTF_8);
    }

    @Benchmark
    public String concatenateStringsByteBufferAllocate() {
        // init new array
        final ByteBuffer buff = ByteBuffer.allocate(TOKEN_HEADER.length + DELIMITER_BYTES.length + TOKEN_PAYLOAD.length + DELIMITER_BYTES.length + TOKEN_SIGNATURE.length);
        buff.put(TOKEN_HEADER);
        buff.put(DELIMITER_BYTES);
        buff.put(TOKEN_PAYLOAD);
        buff.put(DELIMITER_BYTES);
        buff.put(TOKEN_SIGNATURE);
        // return token
        return new String(buff.array(), UTF_8);
    }
}
