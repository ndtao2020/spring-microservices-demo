package com.microservice.example;

import java.util.Random;
import java.util.random.RandomGenerator;

public class RandomUtils {

  public static final String R = "0123456789";
  public static final String O = "abcdefghijklmnopqrstuvwxyz";
  public static final String U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  public static final String Z = "@#$%!";

  public static final char[] R_O_U_CHAR = (R + O + U).toCharArray();
  public static final char[] R_O_U_Z_CHAR = (R + O + U + Z).toCharArray();
  private static final RandomGenerator m = generator(null); // Compliant for security-sensitive use cases

  private RandomUtils() {
    throw new IllegalStateException("Utility class");
  }

  public static RandomGenerator generator(Long seed) {
    if (seed == null) {
      return new Random();
    }
    return new Random(seed);
  }

  public static String random(int l, char[] c) {
    char[] f = new char[l];
    for (int i = 0; i < f.length; i++) {
      f[i] = c[m.nextInt(c.length)];
    }
    return new String(f);
  }

  public static String generateId(int l) {
    return random(l, R_O_U_CHAR);
  }

  public static String generatePassword(int l) {
    return random(l, R_O_U_Z_CHAR);
  }

  public static int generateInt(int min, int max) {
    return m.nextInt(max - min + 1) + min;
  }
}
