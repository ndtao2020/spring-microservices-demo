package com.microservice.benchmark.json;

import com.alibaba.fastjson2.JSON;
import com.cedarsoftware.util.io.JsonWriter;
import com.dslplatform.json.DslJson;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.json.JSONObject;
import org.openjdk.jmh.annotations.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode({Mode.AverageTime, Mode.SingleShotTime})
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class SerializeJsonFromMap {

    public Map<String, String> data = new HashMap<>();

    @Setup
    public void setup() {
        data.put("name", "ndtao2020");
        data.put("country", "Vietnam");
    }

    @Benchmark
    public String jackson() throws JsonProcessingException {
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(data);
    }

    @Benchmark
    public String gson() {
        final Gson gson = new Gson();
        return gson.toJson(data);
    }

    @Benchmark
    public String jSONObject() {
        final JSONObject jsonObject = new JSONObject(data);
        return jsonObject.toString();
    }

    @Benchmark
    public String cedarJsonIO() {
        return JsonWriter.objectToJson(data, Map.of(JsonWriter.TYPE, false));
    }

    @Benchmark
    public String alibabaFastjson2() {
        return JSON.toJSONString(data);
    }

    @Benchmark
    public String dslJson() throws IOException {
        final DslJson<Object> json = new DslJson<>();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            json.serialize(data, stream);
            return stream.toString(StandardCharsets.UTF_8);
        }
    }
}
