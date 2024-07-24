package com.microservice.example.jwt;

import lombok.Data;

@Data
public class Payload {
  private String iss;
  private String sub;
  private String aud;
  private String jti;
  private Long exp;
}
