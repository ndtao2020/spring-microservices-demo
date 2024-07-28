package com.microservice.benchmark.json;

import com.alibaba.fastjson2.JSON;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import groovy.json.JsonGenerator;
import net.minidev.json.JSONValue;
import org.json.JSONObject;
import org.openjdk.jmh.annotations.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
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
  public String alibabaFastjson2() {
    return JSON.toJSONString(data);
  }

  @Benchmark
  public String jsonSmall() {
    return JSONValue.toJSONString(data);
  }

  @Benchmark
  public String groovyJson() {
    final JsonGenerator jsonGenerator = new JsonGenerator.Options().build();
    return jsonGenerator.toJson(data);
  }
}
