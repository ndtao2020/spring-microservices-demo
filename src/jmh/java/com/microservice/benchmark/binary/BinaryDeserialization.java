package com.microservice.benchmark.binary;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.InvalidProtocolBufferException;
import com.microservice.example.RandomUtils;
import com.microservice.example.dto.LoginDTO;
import com.microservice.protobuf.LoginDtoBuf;
import de.undercouch.bson4jackson.BsonFactory;
import io.activej.serializer.BinaryInput;
import io.activej.serializer.BinaryOutput;
import io.activej.serializer.BinarySerializer;
import io.activej.serializer.SerializerFactory;
import org.apache.commons.lang3.SerializationUtils;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class BinaryDeserialization {

  private final BinarySerializer<LoginDTO> serializer = SerializerFactory.defaultInstance().create(LoginDTO.class);
  private final Date aaa = new Date();
  private final com.google.type.Date zzz = com.google.type.Date.newBuilder()
      .setDay(aaa.getDate())
      .setMonth(aaa.getMonth())
      .setYear(aaa.getYear())
      .build();
  private final ObjectMapper bsonMapper = new ObjectMapper(new BsonFactory());
  private final ObjectMapper jacksonMapper = new ObjectMapper();

  byte[] javaBytes;
  byte[] apacheBytes;
  byte[] bsonBytes;
  byte[] jacksonBytes;
  byte[] activejBytes;
  byte[] protobufBytes;

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(BinaryDeserialization.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }

  @Setup
  public void setup() throws NoSuchAlgorithmException, IOException {
    String id = RandomUtils.generateId(50);
    String email = "ndtao2020@proton.me";
    String username = "ndtao2020";
    String password = RandomUtils.generatePassword(20);
    List<String> list = new ArrayList<>();
    list.add("ADMIN");
    list.add("USER");
    // init
    LoginDTO loginDTO = new LoginDTO();
    // init data
    loginDTO.setId(id);
    loginDTO.setEmail(email);
    loginDTO.setUsername(username);
    loginDTO.setPassword(password);
    loginDTO.setAge(30);
    loginDTO.setCreated(aaa);
    loginDTO.setRoles(list);
    loginDTO.setWebsite("https://taoqn.pages.dev");
    // java
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(loginDTO);
      javaBytes = bos.toByteArray();
    }
    // apache
    apacheBytes = SerializationUtils.serialize(loginDTO);
    // activej
    var bo = new BinaryOutput(new byte[200], 0);
    serializer.encode(bo, loginDTO);
    activejBytes = bo.array();
    // bson
    bsonBytes = bsonMapper.writeValueAsBytes(loginDTO);
    // jackson
    jacksonBytes = jacksonMapper.writeValueAsBytes(loginDTO);
    // protobuf
    LoginDtoBuf loginBuf = LoginDtoBuf.newBuilder()
        .setId(id)
        .setEmail(email)
        .setUsername(username)
        .setPassword(password)
        .setAge(30)
        .setCreated(zzz)
        .addAllRoles(list)
        .setWebsite("https://taoqn.pages.dev")
        .build();
    protobufBytes = loginBuf.toByteArray();
  }

  @Benchmark
  public LoginDTO java() throws IOException, ClassNotFoundException {
    try (ByteArrayInputStream bis = new ByteArrayInputStream(javaBytes); ObjectInputStream in = new ObjectInputStream(bis)) {
      return (LoginDTO) in.readObject();
    }
  }

  @Benchmark
  public LoginDTO apache() {
    return SerializationUtils.deserialize(apacheBytes);
  }

  @Benchmark
  public LoginDTO bson() throws IOException {
    return bsonMapper.readValue(bsonBytes, LoginDTO.class);
  }

  @Benchmark
  public LoginDTO jackson() throws IOException {
    return jacksonMapper.readValue(jacksonBytes, LoginDTO.class);
  }

  @Benchmark
  public LoginDTO activej() {
    return serializer.decode(new BinaryInput(activejBytes, 0));
  }

  @Benchmark
  public LoginDtoBuf protobuf() throws InvalidProtocolBufferException {
    return LoginDtoBuf.parseFrom(protobufBytes);
  }
}
