package com.microservice.example.json;

import com.alibaba.fastjson2.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.microservice.example.RandomUtils;
import com.microservice.example.dto.LoginDTO;
import org.json.JSONObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class DeserializeJsonToDTOTests {

    private final String jsonValue = "{\"email\":\"ndtao2020@yopmail.com\",\"username\":\"ndtao2020\",\"password\":\"" + RandomUtils.generatePassword(50) + "\"}";

    @Test
    @DisplayName("Deserialize Json To DTO: Jackson")
    void jackson() throws IOException {
        final ObjectMapper objectMapper = new ObjectMapper();
        LoginDTO dto = objectMapper.readValue(jsonValue, LoginDTO.class);
        assertNotNull(dto);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: Gson")
    void gson() {
        final Gson gson = new Gson();
        LoginDTO dto = gson.fromJson(jsonValue, LoginDTO.class);
        assertNotNull(dto);
    }

    @Test
    @DisplayName("Deserialize Json To DTO: JSONObject")
    void jSONObject() {
        final JSONObject jsonObject = new JSONObject(jsonValue);
        LoginDTO loginDTO = new LoginDTO();
        loginDTO.setEmail(jsonObject.getString("email"));
        loginDTO.setUsername(jsonObject.getString("username"));
        loginDTO.setPassword(jsonObject.getString("password"));

        assertNotNull(loginDTO);
    }

//    @Test
//    @DisplayName("Deserialize Json To DTO: Cedar Software json-io")
//    void cedarJsonIO() {
//        LoginDTO dto = (LoginDTO) JsonReader.jsonToJava(jsonValue);
//        assertNotNull(dto);
//    }

    @Test
    @DisplayName("Deserialize Json To DTO: Alibaba fastjson2")
    void alibabaFastjson2() {
        assertNotNull(JSON.parseObject(jsonValue, LoginDTO.class));
    }

//    @Test
//    @DisplayName("Deserialize Json To DTO: DslJson")
//    void dslJson() throws IOException {
//        final DslJson<Object> json = new DslJson<>();
//        byte[] bytes = jsonValue.getBytes(StandardCharsets.UTF_8);
//        com.dslplatform.json.JsonReader<Object> reader = json.newReader().process(bytes, bytes.length);
//        assertNotNull(reader.next(LoginDTO.class, new LoginDTO()));
//    }
}
