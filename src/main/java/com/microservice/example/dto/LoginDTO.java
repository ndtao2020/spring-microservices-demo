package com.microservice.example.dto;

import lombok.Data;

@Data
public class LoginDTO {
    private String email;
    private String username;
    private String password;
}
