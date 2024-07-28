package com.microservice.example.dto;

import io.activej.serializer.annotations.Serialize;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.List;

@Data
public class LoginDTO implements Serializable {

  @Serial
  private static final long serialVersionUID = -1221L;

  @Serialize
  public String id;
  @Serialize
  public String email;
  @Serialize
  public String username;
  @Serialize
  public String password;
  @Serialize
  public Integer age;
  @Serialize
  public Date created;
  @Serialize
  public List<String> roles;
  @Serialize
  public String website;
}
