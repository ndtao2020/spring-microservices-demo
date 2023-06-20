package com.microservice.example.jwt.ecdsa;

import com.alibaba.fastjson2.JSON;
import com.microservice.example.jwt.Algorithm;
import com.microservice.example.jwt.Payload;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

public class ECDSAJwtParser {

    private final Base64.Decoder decoder = Base64.getUrlDecoder();
    private final ECPublicKey publicKey;
    private final Algorithm algorithm;

    public ECDSAJwtParser(ECPublicKey publicKey, Algorithm algorithm) {
        this.publicKey = publicKey;
        this.algorithm = algorithm;
    }

    public Payload verify(String t) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        String[] r = t.split("\\" + ECDSAJwtBuilder.DELIMITER);
        byte[] n = r[1].getBytes(StandardCharsets.UTF_8);
        if (!verifySignature(r[0].getBytes(StandardCharsets.UTF_8), n, decoder.decode(r[2]))) {
            throw new SignatureException("Token is invalid !");
        }
        Payload payload = JSON.parseObject(decoder.decode(n), Payload.class);
        if (payload.getExp() < System.currentTimeMillis() / 1000) {
            throw new SignatureException("Token is expiration !");
        }
        return payload;
    }

    private boolean verifySignature(byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        final Signature s = Signature.getInstance(algorithm.getJcaName());
        s.initVerify(publicKey);
        s.update(headerBytes);
        s.update((byte) 46);
        s.update(payloadBytes);
        return s.verify(toASN1(signatureBytes));
    }

    private byte[] toASN1(final byte[] encodedSignature) throws IOException {
        int n = encodedSignature.length / 2;
        BigInteger r = new BigInteger(+1, Arrays.copyOfRange(encodedSignature, 0, n));
        BigInteger s = new BigInteger(+1, Arrays.copyOfRange(encodedSignature, n, n * 2));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded();
    }
}
