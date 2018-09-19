package com.hzy.library;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.math.BigInteger;

/**
 * 证书工具类
 * Created by ziye_huang on 2018/9/19.
 */
public class CertUtil {
    private String certString;
    private Certificate cert;

    public CertUtil(String certString) {
        this.certString = certString;
        cert = Certificate.getInstance((Base64.decode(certString)));
    }

    /**
     * 获取证书
     *
     * @return
     */
    public Certificate getCert() {
        return cert;
    }

    /**
     * 获取公钥
     *
     * @return
     */
    public String getPublicKey() {
        byte[] bytes = cert.getTBSCertificate().getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
        byte[] data = new byte[64];
        System.arraycopy(bytes, 1, data, 0, 64);
        return new String(Base64.encode(data));
    }

    /**
     * 验签数据
     *
     * @param inData    原始数据
     * @param signData  签名数据
     * @param publicKey 公钥
     * @return
     */
    public boolean verify(String inData, String signData, String publicKey) {
        boolean ret = false;
        try {
            ret = SM2Util.verifyHash(Base64.decode(publicKey), Base64.decode(inData), Base64.decode(signData));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }


    /**
     * 获取证书序列号
     *
     * @param base64Cert
     * @return
     */
    public String getSerialNumber(String base64Cert) {
        // 解码获取证书字节码数组
        byte[] bytes = Base64.decode(base64Cert);
        // 获取 X509 格式的证书
        Certificate cert = Certificate.getInstance(bytes);
        // 获取证书序列号
        return cert.getSerialNumber().getValue().toString(16);
    }

    /**
     * 将裸签名转换为der格式
     *
     * @param data
     * @return
     */
    private byte[] toDer(byte[] data) {
        try {
            byte[] r32 = new byte[64];
            for (int i = 0; i < 32; i++) {
                r32[i] = 0;
            }
            System.arraycopy(data, 0, r32, 32, 32);
            byte[] s32 = new byte[64];
            for (int i = 0; i < 32; i++) {
                s32[i] = 0;
            }
            System.arraycopy(data, 32, s32, 32, 32);
            ASN1Integer d_r = new ASN1Integer(new BigInteger(r32));
            ASN1Integer d_s = new ASN1Integer(new BigInteger(s32));
            ASN1EncodableVector v2 = new ASN1EncodableVector();
            v2.add(d_r);
            v2.add(d_s);
            DERSequence sign = new DERSequence(v2);
            byte[] ret = sign.getEncoded();
            return ret;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
