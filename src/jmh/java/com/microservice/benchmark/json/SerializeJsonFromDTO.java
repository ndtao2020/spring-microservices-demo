package com.microservice.benchmark.json;

import com.alibaba.fastjson2.JSON;
import com.dslplatform.json.DslJson;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.gson.Gson;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Payload;
import groovy.json.JsonGenerator;
import jakarta.json.Json;
import net.minidev.json.JSONValue;
import org.json.JSONObject;
import org.openjdk.jmh.annotations.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class SerializeJsonFromDTO {

  private static final String AUD = RandomUtils.generateId(10);
  private static final String JWT_ID = RandomUtils.generateId(20);
  private static final String ISSUER = "https://taoqn.pages.dev";
  private static final String SUBJECT = "ndtao2020";
  private static final long EXP = new Date(System.currentTimeMillis() + (60 * 60 * 1000)).getTime();

  private final Payload payload = new Payload();

  @Setup
  public void setup() {
    // init data
    payload.setAud(AUD);
    payload.setJti(JWT_ID);
    payload.setIss(ISSUER);
    payload.setSub(SUBJECT);
    payload.setExp(EXP);
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

//    @Benchmark
//    public String cedarJsonIO() {
//        return JsonWriter.objectToJson(payload, Map.of(JsonWriter.TYPE, false));
//    }

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

  @Benchmark
  public String jakartaJson() {
    return Json.createObjectBuilder()
        .add("aud", AUD)
        .add("jti", JWT_ID)
        .add("iss", ISSUER)
        .add("sub", SUBJECT)
        .add("exp", EXP)
        .build()
        .toString();
  }
}
