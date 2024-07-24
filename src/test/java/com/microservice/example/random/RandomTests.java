package com.microservice.example.random;

import com.microservice.example.RandomUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RandomTests {

  @Test
  @DisplayName("Test Generate Random Id")
  void testGenerateId() {

    int length = 100;

    String password = RandomUtils.generateId(length);

    assertEquals(length, password.length());
  }

  @Test
  @DisplayName("Test Generate Random Password")
  void testGeneratePassword() {

    int length = 100;

    String password = RandomUtils.generatePassword(length);

    assertEquals(length, password.length());
  }
}
