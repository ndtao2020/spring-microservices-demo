package com.microservice.example.binary;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.InvalidProtocolBufferException;
import com.microservice.example.RandomUtils;
import com.microservice.example.dto.LoginDTO;
import com.microservice.protobuf.LoginDtoBuf;
import de.undercouch.bson4jackson.BsonFactory;
import de.undercouch.bson4jackson.BsonParser;
import io.activej.serializer.BinaryInput;
import io.activej.serializer.BinaryOutput;
import io.activej.serializer.BinarySerializer;
import io.activej.serializer.SerializerFactory;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Binary Serialization Tests")
public class BinarySerializationTest {

  static Date currentDate = new Date();
  static BinarySerializer<LoginDTO> serializer = SerializerFactory.defaultInstance().create(LoginDTO.class);

  private static ObjectMapper bsonMapper;
  private static ObjectMapper jacksonMapper;

  @BeforeAll
  static void initAll() {
    // proto
    BsonFactory fac = new BsonFactory();
    fac.enable(BsonParser.Feature.HONOR_DOCUMENT_LENGTH);
    bsonMapper = new ObjectMapper(fac);
    jacksonMapper = new ObjectMapper();
  }

  private LoginDTO buildDto() {
    LoginDTO loginDTO = new LoginDTO();
    // init data
    loginDTO.setId(RandomUtils.generateId(50));
    loginDTO.setEmail("ndtao2020@proton.me");
    loginDTO.setUsername("ndtao2020");
    loginDTO.setPassword(RandomUtils.generatePassword(16));
    loginDTO.setAge(30);
    loginDTO.setCreated(currentDate);
    List<String> list = new ArrayList<>();
    list.add("ADMIN");
    list.add("USER");
    loginDTO.setRoles(list);
    loginDTO.setWebsite("https://taoqn.pages.dev");
    return loginDTO;
  }

  @Test
  void java() throws IOException, ClassNotFoundException {
    LoginDTO loginDTO = buildDto();
    byte[] bytes;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(loginDTO);
      bytes = bos.toByteArray();
    }
    assertNotNull(bytes);
    assertNotEquals(bytes.length, 0);
    try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes); ObjectInputStream in = new ObjectInputStream(bis)) {
      LoginDTO loginDTO1 = (LoginDTO) in.readObject();
      assertEquals(loginDTO, loginDTO1);
    }
  }

  @Test
  void apache() {
    LoginDTO loginDTO = buildDto();
    byte[] bytes = SerializationUtils.serialize(loginDTO);
    assertNotNull(bytes);
    assertNotEquals(bytes.length, 0);
    LoginDTO loginDTO1 = SerializationUtils.deserialize(bytes);
    assertEquals(loginDTO, loginDTO1);
  }

  @Test
  void bson() throws IOException {
    LoginDTO loginDTO = buildDto();
    byte[] bytes = bsonMapper.writeValueAsBytes(loginDTO);
    assertNotNull(bytes);
    assertNotEquals(bytes.length, 0);
    LoginDTO loginDTO1 = bsonMapper.readValue(bytes, LoginDTO.class);
    assertEquals(loginDTO, loginDTO1);
  }

  @Test
  void jackson() throws IOException {
    LoginDTO loginDTO = buildDto();
    byte[] bytes = jacksonMapper.writeValueAsBytes(loginDTO);
    assertNotNull(bytes);
    assertNotEquals(bytes.length, 0);
    LoginDTO loginDTO1 = jacksonMapper.readValue(bytes, LoginDTO.class);
    assertEquals(loginDTO, loginDTO1);
  }

//  @Test
//  void activej() {
//    LoginDTO loginDTO = buildDto();
//    var bo = new BinaryOutput(new byte[200], 0);
//    serializer.encode(bo, loginDTO);
//    byte[] bytes = bo.array();
//    assertNotNull(bytes);
//    assertNotEquals(bytes.length, 0);
//    LoginDTO loginDTO1 = serializer.decode(new BinaryInput(bytes, 0));
//    assertEquals(loginDTO, loginDTO1);
//  }

  @Test
  void protobuf() throws InvalidProtocolBufferException {
    LoginDtoBuf loginBuf = LoginDtoBuf.newBuilder()
        .setId(RandomUtils.generateId(50))
        .setEmail("ndtao2020@proton.me")
        .setUsername("ndtao2020")
        .setPassword(RandomUtils.generatePassword(16))
        .setAge(30)
        .setCreated(
            com.google.type.Date.newBuilder()
                .setDay(currentDate.getDate())
                .setMonth(currentDate.getMonth())
                .setYear(currentDate.getYear())
                .build()
        )
        .addAllRoles(List.of("ADMIN", "USER"))
        .setWebsite("https://taoqn.pages.dev")
        .build();
    byte[] bytes = loginBuf.toByteArray();
    assertNotNull(bytes);
    assertNotEquals(bytes.length, 0);
    assertEquals(loginBuf, LoginDtoBuf.parseFrom(bytes));
  }
}
