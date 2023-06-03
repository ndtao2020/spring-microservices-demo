package com.microservice.benchmark.json;

import com.alibaba.fastjson2.JSON;
import com.cedarsoftware.util.io.JsonWriter;
import com.dslplatform.json.DslJson;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.gson.Gson;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Payload;
import groovy.json.JsonGenerator;
import net.minidev.json.JSONValue;
import org.json.JSONObject;
import org.openjdk.jmh.annotations.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class SerializeJsonFromDTO {

    private final Payload payload = new Payload();

    @Setup
    public void setup() {
        // init data
        payload.setAud(RandomUtils.generateId(10));
        payload.setSub("ndtao2020");
        payload.setIss("https://taoqn.pages.dev");
        payload.setJti(RandomUtils.generateId(20));
        payload.setExp(new Date(System.currentTimeMillis() + (60 * 60 * 1000)).getTime());
    }

    @Benchmark
    public String jackson() throws JsonProcessingException {
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(payload);
    }

    @Benchmark
    public String jacksonObjectWriter() throws JsonProcessingException {
        final ObjectMapper objectMapper = new ObjectMapper();
        final ObjectWriter objectWriter = objectMapper.writerFor(Payload.class);
        return objectWriter.writeValueAsString(payload);
    }

    @Benchmark
    public String gson() {
        final Gson gson = new Gson();
        return gson.toJson(payload);
    }

    @Benchmark
    public String jSONObject() {
        final JSONObject jsonObject = new JSONObject(payload);
        return jsonObject.toString();
    }

    @Benchmark
    public String cedarJsonIO() {
        return JsonWriter.objectToJson(payload, Map.of(JsonWriter.TYPE, false));
    }

    @Benchmark
    public String alibabaFastjson2() {
        return JSON.toJSONString(payload);
    }

    @Benchmark
    public String dslJson() throws IOException {
        final DslJson<Object> json = new DslJson<>();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            json.serialize(payload, stream);
            return stream.toString(StandardCharsets.UTF_8);
        }
    }

    @Benchmark
    public String jsonSmall() {
        return JSONValue.toJSONString(payload);
    }

    @Benchmark
    public String groovyJson() {
        final JsonGenerator jsonGenerator = new JsonGenerator.Options().build();
        return jsonGenerator.toJson(payload);
    }
}
