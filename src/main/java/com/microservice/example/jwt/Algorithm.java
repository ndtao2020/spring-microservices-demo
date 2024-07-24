package com.microservice.example.jwt;

public enum Algorithm {

  HS256("HS256", "HMAC", "HmacSHA256", null, null),
  HS384("HS384", "HMAC", "HmacSHA384", null, null),
  HS512("HS512", "HMAC", "HmacSHA512", null, null),
  RS256("RS256", "RSA", "SHA256withRSA", null, null),
  RS384("RS384", "RSA", "SHA384withRSA", null, null),
  RS512("RS512", "RSA", "SHA512withRSA", null, null),
  ES256("ES256", "ECDSA", "SHA256withECDSA", "secp256r1", 32),
  ES384("ES384", "ECDSA", "SHA384withECDSA", "secp384r1", 48),
  ES512("ES512", "ECDSA", "SHA512withECDSA", "secp512r1", 66),
  ED25519("EdDSA", "EdDSA", "Ed25519", null, null),
  ED448("EdDSA", "EdDSA", "Ed448", null, null);

  private final String value;
  private final String familyName;
  private final String jcaName;
  private final String parameterSpec;
  private final Integer ecNumberSize;

  Algorithm(String value, String familyName, String jcaName, String parameterSpec, Integer ecNumberSize) {
    this.value = value;
    this.familyName = familyName;
    this.jcaName = jcaName;
    this.parameterSpec = parameterSpec;
    this.ecNumberSize = ecNumberSize;
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

  public String getParameterSpec() {
    return parameterSpec;
  }

  public Integer getEcNumberSize() {
    return ecNumberSize;
  }
}
