package com.microservice.benchmark.json;

import com.alibaba.fastjson2.JSON;
import com.cedarsoftware.util.io.JsonObject;
import com.cedarsoftware.util.io.JsonReader;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.microservice.example.RandomUtils;
import com.microservice.example.dto.LoginDTO;
import groovy.json.JsonSlurper;
import net.minidev.json.JSONValue;
import org.apache.groovy.json.internal.LazyMap;
import org.json.JSONObject;
import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class DeserializeJsonToDTO {

    private final String jsonValue = "{\"email\":\"ndtao2020@yopmail.com\",\"username\":\"ndtao2020\",\"password\":\"" + RandomUtils.generatePassword(50) + "\"}";

    @Benchmark
    public LoginDTO jackson() throws IOException {
        final ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(jsonValue, LoginDTO.class);
    }

    @Benchmark
    public LoginDTO gson() {
        final Gson gson = new Gson();
        return gson.fromJson(jsonValue, LoginDTO.class);
    }

    @Benchmark
    public LoginDTO jSONObject() {
        final JSONObject jsonObject = new JSONObject(jsonValue);
        LoginDTO loginDTO = new LoginDTO();
        loginDTO.setEmail(jsonObject.getString("email"));
        loginDTO.setUsername(jsonObject.getString("username"));
        loginDTO.setPassword(jsonObject.getString("password"));
        return loginDTO;
    }

    @Benchmark
    public LoginDTO cedarJsonIO() {
        JsonObject<String, Object> jsonObject = (JsonObject) JsonReader.jsonToJava(jsonValue);

        LoginDTO dto = new LoginDTO();
        dto.setEmail(jsonObject.get("email").toString());
        dto.setUsername(jsonObject.get("username").toString());
        dto.setPassword(jsonObject.get("password").toString());

        return dto;
    }

    @Benchmark
    public LoginDTO alibabaFastjson2() {
        return JSON.parseObject(jsonValue, LoginDTO.class);
    }

    @Benchmark
    public LoginDTO jsonSmall() {
        return JSONValue.parse(jsonValue, LoginDTO.class);
    }

    @Benchmark
    public LoginDTO groovyJson() {
        JsonSlurper jsonSlurper = new JsonSlurper();
        LazyMap map = (LazyMap) jsonSlurper.parseText(jsonValue);

        LoginDTO dto = new LoginDTO();
        dto.setEmail(map.get("email").toString());
        dto.setUsername(map.get("username").toString());
        dto.setPassword(map.get("password").toString());

        return dto;
    }
}
