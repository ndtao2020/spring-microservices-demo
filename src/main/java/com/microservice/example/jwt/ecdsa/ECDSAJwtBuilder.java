package com.microservice.example.jwt.ecdsa;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Headers;
import com.microservice.example.jwt.Payload;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class ECDSAJwtBuilder {

    public static final String DELIMITER = ".";
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Algorithm algorithm;
    private final byte[] headerBytes;
    private final String headerStr;
    private final ECPrivateKey privateKey;

    public ECDSAJwtBuilder(ECPrivateKey privateKey, Algorithm algorithm) {
        this.privateKey = privateKey;
        this.algorithm = algorithm;
        Map<String, String> map = Map.of(Headers.TYPE, "JWT", Headers.ALGORITHM, algorithm.getValue());
        this.headerBytes = encoder.encode(JSON.toJSONBytes(map));
        this.headerStr = new String(headerBytes, UTF_8) + DELIMITER;
    }

    public String compact(Payload payload) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] bytes = encoder.encode(JSON.toJSONBytes(payload));
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update((byte) 46);
        s.update(bytes);
        // convert from the ECDSA JWS signature to the ASN.1/DER encoded signature.
        byte[] asn1Primitive = convertFromASN1toRS(s.sign(), algorithm.getEcNumberSize());
        return headerStr + new String(bytes, UTF_8) + DELIMITER + new String(encoder.encode(asn1Primitive), UTF_8);
    }

    public String compact(Map<String, ?> payloadMap) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        byte[] bytes = encoder.encode(JSON.toJSONBytes(payloadMap));
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initSign(privateKey);
        s.update(headerBytes);
        s.update((byte) 46);
        s.update(bytes);
        // convert from the ECDSA JWS signature to the ASN.1/DER encoded signature.
        byte[] asn1Primitive = convertFromASN1toRS(s.sign(), algorithm.getEcNumberSize());
        return headerStr + new String(bytes, UTF_8) + DELIMITER + new String(encoder.encode(asn1Primitive), UTF_8);
    }

    private byte[] convertFromASN1toRS(byte[] signatureASN1, int size) {
        // Get start and length
        int sequenceR = 2;
        int lengthR = signatureASN1[sequenceR + 1];
        int sequenceS = sequenceR + lengthR + 2;
        int lengthS = signatureASN1[sequenceS + 1];

        // Get offset
        int srcOffsetR = sequenceR + 2;
        int countR = size;
        int dstOffsetR = 0;
        if (lengthR > size) {
            srcOffsetR += lengthR - size;
        } else if (lengthR < size) {
            dstOffsetR += size - lengthR;
            countR -= dstOffsetR;
        }

        int srcOffsetS = sequenceS + 2;
        int countS = size;
        int dstOffsetS = 0;
        if (lengthS > size) {
            srcOffsetS += lengthS - size;
        } else if (lengthS < size) {
            dstOffsetS += size - lengthS;
            countS -= dstOffsetS;
        }

        // Concatenate
        byte[] rs = new byte[2 * size];
        System.arraycopy(signatureASN1, srcOffsetR, rs, dstOffsetR, countR);
        System.arraycopy(signatureASN1, srcOffsetS, rs, dstOffsetR + countR + dstOffsetS, countS);

        return rs;
    }
}
