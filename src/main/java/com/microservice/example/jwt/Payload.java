package com.microservice.example.jwt;

import lombok.Data;

@Data
public class Payload {
    private String iss;
    private String sub;
    private String aud;
    //    private String iat;
    private String jti;
    private Long exp;
}
