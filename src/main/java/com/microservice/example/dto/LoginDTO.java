package com.microservice.example.dto;

import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.List;

@Data
public class LoginDTO implements Serializable {

  @Serial
  private static final long serialVersionUID = -1221L;

  private String id;
  private String email;
  private String username;
  private String password;
  private Integer age;
  private Date created;
  private List<String> roles;
  private String website;
}
