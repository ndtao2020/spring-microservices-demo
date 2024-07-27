package com.microservice.example.jwt;

import lombok.Data;

import java.io.Serial;
import java.io.Serializable;

@Data
public class Payload implements Serializable {

  @Serial
  private static final long serialVersionUID = -16481L;

  private String iss;
  private String sub;
  private String aud;
  private String jti;
  private Long exp;
}
