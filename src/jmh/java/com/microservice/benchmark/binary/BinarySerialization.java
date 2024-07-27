package com.microservice.benchmark.binary;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Output;
import com.microservice.example.RandomUtils;
import com.microservice.example.dto.LoginDTO;
import com.microservice.protobuf.LoginDtoBuf;
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
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Threads(Threads.MAX)
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class BinarySerialization {

  private final Date currentDate = new Date();
  private final BinarySerializer<LoginDTO> serializer = SerializerFactory.defaultInstance().create(LoginDTO.class);
  private final LoginDTO loginDTO = new LoginDTO();
  private LoginDtoBuf loginBuf;

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
        .include(BinarySerialization.class.getSimpleName())
        .warmupIterations(1)
        .forks(1)
        .build();
    new Runner(opt).run();
  }

  @Setup
  public void setup() {
    // init data
    loginDTO.setId(RandomUtils.generateId(50));
    loginDTO.setEmail("ndtao2020@proton.me");
    loginDTO.setUsername("ndtao2020");
    loginDTO.setPassword(RandomUtils.generatePassword(16));
    loginDTO.setAge(30);
    loginDTO.setCreated(currentDate);
    loginDTO.setRoles(List.of("ADMIN", "USER"));
    loginDTO.setWebsite("https://taoqn.pages.dev");
    // proto
    loginBuf = LoginDtoBuf.newBuilder()
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
  }

  @Benchmark
  public byte[] java() throws IOException {
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(loginDTO);
      return bos.toByteArray();
    }
  }

  @Benchmark
  public byte[] apache() {
    return SerializationUtils.serialize(loginDTO);
  }

  @Benchmark
  public byte[] activej() {
    var bo = new BinaryOutput(new byte[200], 0);
    serializer.encode(bo, loginDTO);
    return bo.array();
  }

  @Benchmark
  public byte[] protobuf() {
    return loginBuf.toByteArray();
  }

  @Benchmark
  public byte[] kyro() throws IOException {
    Kryo kryo = new Kryo();
    kryo.register(LoginDTO.class);
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream(); Output output = new Output(bos)) {
      kryo.writeObject(output, loginDTO);
      return bos.toByteArray();
    }
  }
}
