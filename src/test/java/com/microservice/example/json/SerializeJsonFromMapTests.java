package com.microservice.example.json;

import com.alibaba.fastjson2.JSON;
import com.cedarsoftware.util.io.JsonWriter;
import com.dslplatform.json.DslJson;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import groovy.json.JsonGenerator;
import net.minidev.json.JSONValue;
import org.json.JSONObject;
import org.junit.jupiter.api.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

class SerializeJsonFromMapTests {

    static Map<String, String> data = new HashMap<>();
    static String originalJsonData = "";

    @BeforeAll
    static void initAll() {
        data.put("CS", "Post1");
        data.put("Linux", "Post1");
        data.put("Kotlin", "Post1");
        originalJsonData = JSON.toJSONString(data);
    }

    @AfterAll
    static void tearDownAll() {
    }

    @BeforeEach
    void init() {
    }

    @Test
    @DisplayName("Map to Json: Jackson")
    void jackson() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Assertions.assertEquals(originalJsonData, objectMapper.writeValueAsString(data));
    }

    @Test
    @DisplayName("Map to Json: Gson")
    void gson() {
        Gson gson = new Gson();
        Assertions.assertEquals(originalJsonData, gson.toJson(data));
    }

    @Test
    @DisplayName("Map to Json: JSONObject")
    void jSONObject() {
        JSONObject jsonObject = new JSONObject(data);
        Assertions.assertEquals(originalJsonData, jsonObject.toString());
    }

    @Test
    @DisplayName("Map to Json: Cedar Software json-io")
    void cedarJsonIO() {
        Assertions.assertEquals(originalJsonData, JsonWriter.objectToJson(data, Map.of(JsonWriter.TYPE, false)));
    }

    @Test
    @DisplayName("Map to Json: Alibaba fastjson2")
    void alibabaFastjson2() {
        Assertions.assertEquals(originalJsonData, JSON.toJSONString(data));
    }

    @Test
    @DisplayName("Map to Json: DslJson")
    void dslJson() throws IOException {
        DslJson<Object> json = new DslJson<>();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            json.serialize(data, stream); //will use thread local writer
            Assertions.assertEquals(originalJsonData, stream.toString(StandardCharsets.UTF_8));
        }
    }

    @Test
    @DisplayName("Map to Json: JSON Small")
    void jsonSmall() {
        Assertions.assertEquals(originalJsonData, JSONValue.toJSONString(data));
    }

    @Test
    @DisplayName("Map to Json: Groovy Json")
    void groovyJson() {
        JsonGenerator jsonGenerator = new JsonGenerator.Options().build();
        Assertions.assertEquals(originalJsonData, jsonGenerator.toJson(data));
    }

    @AfterEach
    void tearDown() {
    }
}
