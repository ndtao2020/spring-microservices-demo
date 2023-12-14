package com.microservice.benchmark.json;

import com.alibaba.fastjson2.JSON;
import com.cedarsoftware.util.io.JsonObject;
import com.cedarsoftware.util.io.JsonReader;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Claims;
import com.microservice.example.jwt.Payload;
import groovy.json.JsonSlurper;
import net.minidev.json.JSONValue;
import org.apache.groovy.json.internal.LazyMap;
import org.json.JSONObject;
import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class DeserializeJsonToDTO {

    private String jsonValue = null;

    @Setup
    public void setup() {
        // init data
        Payload payload = new Payload();
        payload.setAud(RandomUtils.generateId(10));
        payload.setSub("ndtao2020");
        payload.setIss("https://taoqn.pages.dev");
        payload.setJti(RandomUtils.generateId(20));
        payload.setExp(new Date(System.currentTimeMillis() + (60 * 60 * 1000)).getTime());
        // Serialize Json
        jsonValue = JSON.toJSONString(payload);
    }

    @Benchmark
    public Payload jackson() throws IOException {
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(jsonValue, Payload.class);
    }

    @Benchmark
    public Payload gson() {
        final Gson gson = new Gson();
        return gson.fromJson(jsonValue, Payload.class);
    }

    @Benchmark
    public Payload jSONObject() {
        final JSONObject jsonObject = new JSONObject(jsonValue);
        Payload dto = new Payload();
        dto.setAud(jsonObject.getString(Claims.AUDIENCE));
        dto.setSub(jsonObject.getString(Claims.SUBJECT));
        dto.setIss(jsonObject.getString(Claims.ISSUER));
        dto.setJti(jsonObject.getString(Claims.JWT_ID));
        dto.setExp(jsonObject.getLong(Claims.EXPIRES_AT));
        return dto;
    }

    @Benchmark
    public Payload cedarJsonIO() {
        final JsonObject jsonObject = (JsonObject) JsonReader.jsonToJava(jsonValue);

        Payload dto = new Payload();

        dto.setAud(jsonObject.get(Claims.AUDIENCE).toString());
        dto.setSub(jsonObject.get(Claims.SUBJECT).toString());
        dto.setIss(jsonObject.get(Claims.ISSUER).toString());
        dto.setJti(jsonObject.get(Claims.JWT_ID).toString());
        dto.setExp(Long.parseLong(jsonObject.get(Claims.EXPIRES_AT).toString()));

        return dto;
    }

    @Benchmark
    public Payload alibabaFastjson2() {
        return JSON.parseObject(jsonValue, Payload.class);
    }

    @Benchmark
    public Payload jsonSmall() {
        return JSONValue.parse(jsonValue, Payload.class);
    }

    @Benchmark
    public Payload groovyJson() {
        final JsonSlurper jsonSlurper = new JsonSlurper();
        final LazyMap jsonObject = (LazyMap) jsonSlurper.parseText(jsonValue);

        Payload dto = new Payload();

        dto.setAud(jsonObject.get(Claims.AUDIENCE).toString());
        dto.setSub(jsonObject.get(Claims.SUBJECT).toString());
        dto.setIss(jsonObject.get(Claims.ISSUER).toString());
        dto.setJti(jsonObject.get(Claims.JWT_ID).toString());
        dto.setExp(Long.parseLong(jsonObject.get(Claims.EXPIRES_AT).toString()));

        return dto;
    }
}
