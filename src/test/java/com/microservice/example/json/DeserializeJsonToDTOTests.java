package com.microservice.example.json;

import com.alibaba.fastjson2.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.gson.Gson;
import com.microservice.example.RandomUtils;
import com.microservice.example.jwt.Claims;
import com.microservice.example.jwt.Payload;
import groovy.json.JsonSlurper;
import net.minidev.json.JSONValue;
import org.apache.groovy.json.internal.LazyMap;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DeserializeJsonToDTOTests {

  public static Payload payload = new Payload();
  public static String jsonValue = null;

  @BeforeAll
  static void initAll() {
    // init data
    payload.setAud(RandomUtils.generateId(10));
    payload.setSub("ndtao2020");
    payload.setIss("https://taoqn.pages.dev");
    payload.setJti(RandomUtils.generateId(20));
    payload.setExp(new Date(System.currentTimeMillis() + (60 * 60 * 1000)).getTime());
    // Serialize Json
    jsonValue = JSON.toJSONString(payload);
  }

  @Test
  @DisplayName("Deserialize Json To DTO: Jackson")
  void jackson() throws IOException {
    ObjectMapper objectMapper = new ObjectMapper();
    assertEquals(payload, objectMapper.readValue(jsonValue, Payload.class));
  }

  @Test
  @DisplayName("Deserialize Json To DTO: Jackson - ObjectReader")
  void jacksonObjectReader() throws IOException {
    ObjectMapper objectMapper = new ObjectMapper();
    ObjectReader objectReader = objectMapper.readerFor(Payload.class);
    assertEquals(payload, objectReader.readValue(jsonValue, Payload.class));
  }

  @Test
  @DisplayName("Deserialize Json To DTO: Gson")
  void gson() {
    final Gson gson = new Gson();
    assertEquals(payload, gson.fromJson(jsonValue, Payload.class));
  }

  @Test
  @DisplayName("Deserialize Json To DTO: JSONObject")
  void jSONObject() {
    JSONObject jsonObject = new JSONObject(jsonValue);

    Payload dto = new Payload();
    dto.setAud(jsonObject.getString(Claims.AUDIENCE));
    dto.setSub(jsonObject.getString(Claims.SUBJECT));
    dto.setIss(jsonObject.getString(Claims.ISSUER));
    dto.setJti(jsonObject.getString(Claims.JWT_ID));
    dto.setExp(jsonObject.getLong(Claims.EXPIRES_AT));

    assertEquals(payload, dto);
  }

  @Test
  @DisplayName("Deserialize Json To DTO: Alibaba fastjson2")
  void alibabaFastjson2() {
    assertEquals(payload, JSON.parseObject(jsonValue, Payload.class));
  }

  @Test
  @DisplayName("Deserialize Json To DTO: JSON Small")
  void jsonSmall() {
    assertEquals(payload, JSONValue.parse(jsonValue, Payload.class));
  }

  @Test
  @DisplayName("Deserialize Json To DTO: Groovy Json")
  void groovyJson() {
    JsonSlurper jsonSlurper = new JsonSlurper();
    LazyMap jsonObject = (LazyMap) jsonSlurper.parseText(jsonValue);

    Payload dto = new Payload();

    dto.setAud(jsonObject.get(Claims.AUDIENCE).toString());
    dto.setSub(jsonObject.get(Claims.SUBJECT).toString());
    dto.setIss(jsonObject.get(Claims.ISSUER).toString());
    dto.setJti(jsonObject.get(Claims.JWT_ID).toString());
    dto.setExp(Long.parseLong(jsonObject.get(Claims.EXPIRES_AT).toString()));

    assertEquals(payload, dto);
  }
}
