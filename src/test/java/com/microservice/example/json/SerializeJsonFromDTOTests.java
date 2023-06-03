package com.microservice.example.json;

import com.alibaba.fastjson2.JSON;
import com.cedarsoftware.util.io.JsonWriter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.gson.Gson;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Payload;
import groovy.json.JsonGenerator;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SerializeJsonFromDTOTests {

    static Payload payload = new Payload();
    static String originalJsonData = "";

    @BeforeAll
    static void initAll() {
        // init data
        payload.setAud(RandomUtils.generateId(10));
        payload.setSub("ndtao2020");
        payload.setIss("https://taoqn.pages.dev");
        payload.setJti(RandomUtils.generateId(20));
        payload.setExp(new Date(System.currentTimeMillis() + (60 * 60 * 1000)).getTime());
        // to json
        originalJsonData = JSON.toJSONString(payload);
    }

    @Test
    @DisplayName("DTO to Json: Jackson")
    void jackson() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        assertEquals(originalJsonData.length(), objectMapper.writeValueAsString(payload).length());
    }

    @Test
    @DisplayName("DTO to Json: Jackson ObjectWriter")
    void jacksonObjectWriter() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        ObjectWriter objectWriter = objectMapper.writerFor(Payload.class);
        assertEquals(originalJsonData.length(), objectWriter.writeValueAsString(payload).length());
    }

    @Test
    @DisplayName("DTO to Json: Gson")
    void gson() {
        Gson gson = new Gson();
        assertEquals(originalJsonData.length(), gson.toJson(payload).length());
    }

    @Test
    @DisplayName("DTO to Json: JSONObject")
    void jSONObject() {
        JSONObject jsonObject = new JSONObject(payload);
        assertEquals(originalJsonData.length(), jsonObject.toString().length());
    }

    @Test
    @DisplayName("DTO to Json: Cedar Software json-io")
    void cedarJsonIO() {
        assertEquals(originalJsonData.length(), JsonWriter.objectToJson(payload, Map.of(JsonWriter.TYPE, false)).length());
    }

    @Test
    @DisplayName("DTO to Json: Alibaba fastjson2")
    void alibabaFastjson2() {
        assertEquals(originalJsonData.length(), JSON.toJSONString(payload).length());
    }

    @Test
    @DisplayName("DTO to Json: Groovy Json")
    void groovyJson() {
        JsonGenerator jsonGenerator = new JsonGenerator.Options().build();
        assertEquals(originalJsonData.length(), jsonGenerator.toJson(payload).length());
    }
}
