package com.microservice.example.jwt;

public enum Algorithm {

    HS256("HS256", "HMAC", "HmacSHA256"),

    HS384("HS384", "HMAC", "HmacSHA384"),

    HS512("HS512", "HMAC", "HmacSHA512"),

    RS256("RS256", "RSA", "SHA256withRSA"),

    RS384("RS384", "RSA", "SHA384withRSA"),

    RS512("RS512", "RSA", "SHA512withRSA");

    private final String value;
    private final String familyName;
    private final String jcaName;

    Algorithm(String value, String familyName, String jcaName) {
        this.value = value;
        this.familyName = familyName;
        this.jcaName = jcaName;
    }

    public String getValue() {
        return value;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getJcaName() {
        return jcaName;
    }
}
