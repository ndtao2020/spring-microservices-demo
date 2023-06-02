package com.microservice.example.json;

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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class DeserializeJsonToDTOTests {

    public static LoginDTO loginDTO = new LoginDTO();
    public static String jsonValue = null;

    @BeforeAll
    static void initAll() {
        // init data
        loginDTO.setEmail("ndtao2020@yopmail.com");
        loginDTO.setUsername("ndtao2020");
        loginDTO.setPassword(RandomUtils.generatePassword(50));
        // Serialize Json
        jsonValue = JSON.toJSONString(loginDTO);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: Jackson")
    void jackson() throws IOException {
        final ObjectMapper objectMapper = new ObjectMapper();
        LoginDTO dto = objectMapper.readValue(jsonValue, LoginDTO.class);
        assertNotNull(dto);
        assertEquals(loginDTO, dto);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: Gson")
    void gson() {
        final Gson gson = new Gson();
        LoginDTO dto = gson.fromJson(jsonValue, LoginDTO.class);
        assertNotNull(dto);
        assertEquals(loginDTO, dto);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: JSONObject")
    void jSONObject() {
        final JSONObject jsonObject = new JSONObject(jsonValue);

        LoginDTO dto = new LoginDTO();
        dto.setEmail(jsonObject.getString("email"));
        dto.setUsername(jsonObject.getString("username"));
        dto.setPassword(jsonObject.getString("password"));

        assertNotNull(dto);
        assertEquals(loginDTO, dto);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: Cedar Software json-io")
    void cedarJsonIO() {
        JsonObject<String, Object> jsonObject = (JsonObject) JsonReader.jsonToJava(jsonValue);

        LoginDTO dto = new LoginDTO();
        dto.setEmail(jsonObject.get("email").toString());
        dto.setUsername(jsonObject.get("username").toString());
        dto.setPassword(jsonObject.get("password").toString());

        assertNotNull(dto);
        assertEquals(loginDTO, dto);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: Alibaba fastjson2")
    void alibabaFastjson2() {
        LoginDTO dto = JSON.parseObject(jsonValue, LoginDTO.class);
        assertNotNull(dto);
        assertEquals(loginDTO, dto);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: JSON Small")
    void jsonSmall() {
        LoginDTO dto = JSONValue.parse(jsonValue, LoginDTO.class);
        assertNotNull(dto);
        assertEquals(loginDTO, dto);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: Groovy Json")
    void groovyJson() {
        JsonSlurper jsonSlurper = new JsonSlurper();
        LazyMap map = (LazyMap) jsonSlurper.parseText(jsonValue);

        LoginDTO dto = new LoginDTO();
        dto.setEmail(map.get("email").toString());
        dto.setUsername(map.get("username").toString());
        dto.setPassword(map.get("password").toString());

        assertEquals(loginDTO, dto);
    }
}
