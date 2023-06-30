package com.microservice.benchmark;

import org.openjdk.jmh.annotations.*;

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
    public String concatenateStringsWithStringBuilder() {
        StringBuilder builder = new StringBuilder();
        builder.append(new String(TOKEN_HEADER, UTF_8));
        builder.append(DELIMITER);
        builder.append(new String(TOKEN_PAYLOAD, UTF_8));
        builder.append(DELIMITER);
        builder.append(new String(TOKEN_SIGNATURE, UTF_8));
        return builder.toString();
    }

    @Benchmark
    public String concatenateStringsWithArrays() {
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
}
