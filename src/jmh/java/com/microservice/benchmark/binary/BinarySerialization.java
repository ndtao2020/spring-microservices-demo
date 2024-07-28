package com.microservice.benchmark.binary;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microservice.example.RandomUtils;
import com.microservice.example.dto.LoginDTO;
import com.microservice.protobuf.LoginDtoBuf;
import de.undercouch.bson4jackson.BsonFactory;
import io.activej.serializer.BinaryOutput;
import io.activej.serializer.BinarySerializer;
import io.activej.serializer.SerializerFactory;
import org.apache.commons.lang3.SerializationUtils;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class BinarySerialization {

  private final BinarySerializer<LoginDTO> serializer = SerializerFactory.defaultInstance().create(LoginDTO.class);
  private final Date aaa = new Date();
  private final com.google.type.Date zzz = com.google.type.Date.newBuilder()
      .setDay(aaa.getDate())
      .setMonth(aaa.getMonth())
      .setYear(aaa.getYear())
      .build();
  private final ObjectMapper bsonMapper = new ObjectMapper(new BsonFactory());
  private final ObjectMapper jacksonMapper = new ObjectMapper();


  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(BinarySerialization.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }

  private LoginDTO buildDto() {
    LoginDTO loginDTO = new LoginDTO();
    // init data
    loginDTO.setId(RandomUtils.generateId(50));
    loginDTO.setEmail("ndtao2020@proton.me");
    loginDTO.setUsername("ndtao2020");
    loginDTO.setPassword(RandomUtils.generatePassword(16));
    loginDTO.setAge(30);
    loginDTO.setCreated(aaa);
    List<String> list = new ArrayList<>();
    list.add("ADMIN");
    list.add("USER");
    loginDTO.setRoles(list);
    loginDTO.setWebsite("https://taoqn.pages.dev");
    return loginDTO;
  }

  @Benchmark
  public byte[] java() throws IOException {
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(buildDto());
      return bos.toByteArray();
    }
  }

  @Benchmark
  public byte[] apache() {
    return SerializationUtils.serialize(buildDto());
  }

  @Benchmark
  public byte[] bson() throws JsonProcessingException {
    return bsonMapper.writeValueAsBytes(buildDto());
  }

  @Benchmark
  public byte[] jackson() throws JsonProcessingException {
    return jacksonMapper.writeValueAsBytes(buildDto());
  }

  @Benchmark
  public byte[] activej() {
    var bo = new BinaryOutput(new byte[200], 0);
    serializer.encode(bo, buildDto());
    return bo.array();
  }

  @Benchmark
  public byte[] protobuf() {
    List<String> list = new ArrayList<>();
    list.add("ADMIN");
    list.add("USER");
    LoginDtoBuf loginBuf = LoginDtoBuf.newBuilder()
        .setId(RandomUtils.generateId(50))
        .setEmail("ndtao2020@proton.me")
        .setUsername("ndtao2020")
        .setPassword(RandomUtils.generatePassword(16))
        .setAge(30)
        .setCreated(zzz)
        .addAllRoles(list)
        .setWebsite("https://taoqn.pages.dev")
        .build();
    return loginBuf.toByteArray();
  }
}
