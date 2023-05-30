package com.microservice.benchmark.json;

import com.alibaba.fastjson2.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.microservice.example.RandomUtils;
import com.microservice.example.dto.LoginDTO;
import org.json.JSONObject;
import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
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

//    @Benchmark
//    public LoginDTO cedarJsonIO() {
//        return (LoginDTO) JsonReader.jsonToJava(jsonValue);
//    }

    @Benchmark
    public LoginDTO alibabaFastjson2() {
        return JSON.parseObject(jsonValue, LoginDTO.class);
    }

//    @Benchmark
//    public LoginDTO dslJson() throws IOException {
//        final DslJson<Object> json = new DslJson<>();
//        byte[] bytes = jsonValue.getBytes(StandardCharsets.UTF_8);
//        com.dslplatform.json.JsonReader<Object> reader = json.newReader().process(bytes, bytes.length);
//        LoginDTO instance = new LoginDTO(); //can be reused
//        return reader.next(LoginDTO.class, instance); //bound is the same as instance above
//    }
}
