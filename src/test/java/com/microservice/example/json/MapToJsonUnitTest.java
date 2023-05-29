package com.microservice.example.json;

import com.alibaba.fastjson2.JSON;
import com.cedarsoftware.util.io.JsonWriter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.json.JSONObject;
import org.junit.jupiter.api.*;

import java.util.HashMap;
import java.util.Map;

@DisplayName("Map to Json - Test case")
class MapToJsonUnitTest {

    static String originalJsonData = "{\"CS\":\"Post1\",\"Linux\":\"Post1\",\"Kotlin\":\"Post1\"}";
    static Map<String, String> data = new HashMap<>();

    @BeforeAll
    static void initAll() {
        data.put("CS", "Post1");
        data.put("Linux", "Post1");
        data.put("Kotlin", "Post1");
    }

    @BeforeEach
    void init() {
    }

    @Test
    @DisplayName("Map to Json: Jackson")
    void given_HashMapData_whenUsingJackson_thenConvertToJson() throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Assertions.assertEquals(originalJsonData, objectMapper.writeValueAsString(data));
    }

    @Test
    @DisplayName("Map to Json: Gson")
    void given_HashMapData_whenUsingGson_thenConvertToJson() {
        Gson gson = new Gson();
        Assertions.assertEquals(originalJsonData, gson.toJson(data));
    }

    @Test
    @DisplayName("Map to Json: JSONObject")
    void given_HashMapData_whenOrgJson_thenConvertToJsonUsing() {
        JSONObject jsonObject = new JSONObject(data);
        Assertions.assertEquals(originalJsonData, jsonObject.toString());
    }

    @Test
    @DisplayName("Map to Json: Cedar Software json-io")
    void given_HashMapData_whenJson_io_thenConvertToJsonUsing() {
        Map<String, Object> args = new HashMap<>();
        args.put(JsonWriter.TYPE, false);
        Assertions.assertEquals(originalJsonData, JsonWriter.objectToJson(data, args));
    }

    @Test
    @DisplayName("Map to Json: Alibaba fastjson2")
    void given_HashMapData_whenAlibaba_thenConvertToJsonUsing() {
        Assertions.assertEquals(originalJsonData, JSON.toJSONString(data));
    }

    @AfterEach
    void tearDown() {
    }

    @AfterAll
    static void tearDownAll() {
    }
}
