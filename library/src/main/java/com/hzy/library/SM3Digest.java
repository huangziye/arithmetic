package com.hzy.library;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;

/**
 * Created by ziye_huang on 2018/9/19.
 */
public class SM3Digest {
    /**
     * SM3值的长度
     */
    private static final int BYTE_LENGTH = 32;

    /**
     * SM3分组长度
     */
    private static final int BLOCK_LENGTH = 64;

    /**
     * 缓冲区长度
     */
    private static final int BUFFER_LENGTH = BLOCK_LENGTH * 1;

    /**
     * 缓冲区
     */
    private byte[] xBuf = new byte[BUFFER_LENGTH];

    /**
     * 缓冲区偏移量
     */
    private int xBufOff;

    /**
     * 初始向量
     */
    private byte[] V = SM3.iv.clone();

    private int cntBlock = 0;

    public SM3Digest() {
    }

    public SM3Digest(SM3Digest t) {
        System.arraycopy(t.xBuf, 0, this.xBuf, 0, t.xBuf.length);
        this.xBufOff = t.xBufOff;
        System.arraycopy(t.V, 0, this.V, 0, t.V.length);
    }

    /**
     * SM3结果输出
     *
     * @param out    保存SM3结构的缓冲区
     * @param outOff 缓冲区偏移量
     * @return
     */
    public int doFinal(byte[] out, int outOff) {
        byte[] tmp = doFinal();
        System.arraycopy(tmp, 0, out, 0, tmp.length);
        return BYTE_LENGTH;
    }

    public void reset() {
        xBufOff = 0;
        cntBlock = 0;
        V = SM3.iv.clone();
    }

    /**
     * 明文输入
     *
     * @param in    明文输入缓冲区
     * @param inOff 缓冲区偏移量
     * @param len   明文长度
     */
    public void update(byte[] in, int inOff, int len) {
        int partLen = BUFFER_LENGTH - xBufOff;
        int inputLen = len;
        int dPos = inOff;
        if (partLen < inputLen) {
            System.arraycopy(in, dPos, xBuf, xBufOff, partLen);
            inputLen -= partLen;
            dPos += partLen;
            doUpdate();
            while (inputLen > BUFFER_LENGTH) {
                System.arraycopy(in, dPos, xBuf, 0, BUFFER_LENGTH);
                inputLen -= BUFFER_LENGTH;
                dPos += BUFFER_LENGTH;
                doUpdate();
            }
        }

        System.arraycopy(in, dPos, xBuf, xBufOff, inputLen);
        xBufOff += inputLen;
    }

    private void doUpdate() {
        byte[] B = new byte[BLOCK_LENGTH];
        for (int i = 0; i < BUFFER_LENGTH; i += BLOCK_LENGTH) {
            System.arraycopy(xBuf, i, B, 0, B.length);
            doHash(B);
        }
        xBufOff = 0;
    }

    private void doHash(byte[] B) {
        byte[] tmp = SM3.CF(V, B);
        System.arraycopy(tmp, 0, V, 0, V.length);
        cntBlock++;
    }

    private byte[] doFinal() {
        byte[] B = new byte[BLOCK_LENGTH];
        byte[] buffer = new byte[xBufOff];
        System.arraycopy(xBuf, 0, buffer, 0, buffer.length);
        byte[] tmp = SM3.padding(buffer, cntBlock);
        for (int i = 0; i < tmp.length; i += BLOCK_LENGTH) {
            System.arraycopy(tmp, i, B, 0, B.length);
            doHash(B);
        }
        return V;
    }

    public void update(byte in) {
        byte[] buffer = new byte[]{in};
        update(buffer, 0, 1);
    }

    public int getDigestSize() {
        return BYTE_LENGTH;
    }

    public static void main(String[] args) {
        String cert = "MIID3TCCA4KgAwIBAgIIPfUAhQAARIcwDAYIKoEcz1UBg3UFADBpMQswCQYDVQQGEwJDTjE8MDoGA1UECgwzTmF0aW9uYWwgRS1Hb3Zlcm5tZW50IE5ldHdvcmsgQWRtaW5pc3RyYXRpb24gQ2VudGVyMRwwGgYDVQQDDBNDRUdOIFNNMiBDbGFzcyAyIENBMB4XDTE3MDYyMDA5MTQ1OFoXDTIyMDYyMDA5MTQ1OFowWzELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCea1meaxn+ecgTEbMBkGA1UEKgwSMTEzMzAxMDAwMDI0ODk1MjQyMRswGQYDVQQDDBLmna3lt57luILmsJHmlL/lsYAwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAT7WEP7/sfI2JLbLI0yYBEND+nx+URgX5tofEnJ2F5V9a5e5gprkCIrM6RAtr2FODZKGTYyRwzCskJJNOqBAulso4ICHjCCAhowDAYDVR0TBAUwAwEBADAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDgYDVR0PAQH/BAQDAgDAMBEGCWCGSAGG+EIBAQQEAwIAgDAfBgNVHSMEGDAWgBS5wIwzgZ6w+qF7I3I/Q5TuqdZ+fTCBxQYDVR0fBIG9MIG6MIG3oIG0oIGxhoGubGRhcDovL2xkYXAuc3RhdGVjYS5jZWduLmNuOjM4OS9DTj1DRUdOIFNNMiBDbGFzcyAyIENBLENOPUNFR04gU00yIENsYXNzIDIgQ0EsIE9VPUNSTERpc3RyaWJ1dGVQb2ludHMsIG89c2ljY2E/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdGNsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG/BggrBgEFBQcBAQSBsjCBrzCBrAYIKwYBBQUHMAKGgZ9sZGFwOi8vbGRhcC5zdGF0ZWNhLmNlZ24uY246Mzg5L0NOPUNFR04gU00yIENsYXNzIDIgQ0EsQ049Q0VHTiBTTTIgQ2xhc3MgMiBDQSwgT1U9Y0FDZXJ0aWZpY2F0ZXMsIG89c2ljY2E/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwHQYDVR0OBBYEFNJ8FTMBH6r3DLBs3aX48SmSQ5kVMAwGCCqBHM9VAYN1BQADRwAwRAIgLfKHEy7eoBy57TIhfRI9olcCWUnhgcIz3oR+ytxnlSwCIFKaDBSJyHgUynx3flmTcdC94bpkDdeMqsrJxzL3jj+G";
        String pk = "+1hD+/7HyNiS2yyNMmARDQ/p8flEYF+baHxJydheVfWuXuYKa5AiKzOkQLa9hTg2Shk2MkcMwrJCSTTqgQLpbA==";
        byte[] cspk = getCSPK(org.bouncycastle.util.encoders.Base64.decode(cert));
        byte[] decode = org.bouncycastle.util.encoders.Base64.decode(pk);
        byte[] md = new byte[32];
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        try {
        } catch (Exception e) {
            e.printStackTrace();
        }


        System.arraycopy(cspk, 0, x, 0, 32);
        System.arraycopy(cspk, 32, y, 0, 32);

        byte[] msg = "1111".getBytes();
        SM3Digest sm3 = new SM3Digest();
        byte[] sm2GetZ = SM2.Instance().sm2GetZ("1234567812345678".getBytes(), x, y);
        String sm2GetZStr = new String(org.bouncycastle.util.encoders.Base64.encode(sm2GetZ));
        System.out.println(sm2GetZStr);
        sm3.update(sm2GetZ, 0, sm2GetZ.length);
        sm3.update(msg, 0, msg.length);
        sm3.doFinal(md, 0);
        String mdStr = new String(Base64.encode(md));
        System.out.println(mdStr);


    }

    /**
     * 返回SM3 Hash
     *
     * @param cert   证书
     * @param pubKey 公钥
     * @return
     */
    public static String sm3Hash(String cert, String pubKey, String data) {
        byte[] cspk = getCSPK(org.bouncycastle.util.encoders.Base64.decode(cert));
        byte[] decode = org.bouncycastle.util.encoders.Base64.decode(pubKey);
        byte[] md = new byte[32];
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        try {
        } catch (Exception e) {
            e.printStackTrace();
        }


        System.arraycopy(cspk, 0, x, 0, 32);
        System.arraycopy(cspk, 32, y, 0, 32);

        byte[] msg = data.getBytes();
        SM3Digest sm3 = new SM3Digest();
        byte[] sm2GetZ = SM2.Instance().sm2GetZ("1234567812345678".getBytes(), x, y);
        String sm2GetZStr = new String(org.bouncycastle.util.encoders.Base64.encode(sm2GetZ));
        System.out.println(sm2GetZStr);
        sm3.update(sm2GetZ, 0, sm2GetZ.length);
        sm3.update(msg, 0, msg.length);
        sm3.doFinal(md, 0);
        String mdStr = new String(org.bouncycastle.util.encoders.Base64.encode(md));
        System.err.println("mdStr=" + mdStr);
        return mdStr;
    }

    /**
     * 返回SM3 Hash
     *
     * @param cert   证书
     * @param pubKey 公钥
     * @return
     */
    public static String sm3Hash(String cert, String pubKey, byte[] data) {
        byte[] cspk = getCSPK(org.bouncycastle.util.encoders.Base64.decode(cert));
        byte[] decode = org.bouncycastle.util.encoders.Base64.decode(pubKey);
        byte[] md = new byte[32];
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        try {
        } catch (Exception e) {
            e.printStackTrace();
        }


        System.arraycopy(cspk, 0, x, 0, 32);
        System.arraycopy(cspk, 32, y, 0, 32);

        SM3Digest sm3 = new SM3Digest();
        byte[] sm2GetZ = SM2.Instance().sm2GetZ("1234567812345678".getBytes(), x, y);
        String sm2GetZStr = new String(org.bouncycastle.util.encoders.Base64.encode(sm2GetZ));
        System.out.println(sm2GetZStr);
        sm3.update(sm2GetZ, 0, sm2GetZ.length);
        sm3.update(data, 0, data.length);
        sm3.doFinal(md, 0);
        String mdStr = new String(org.bouncycastle.util.encoders.Base64.encode(md));
        System.err.println("mdStr=" + mdStr);
        return mdStr;
    }


    public static byte[] getCSPK(byte[] csCert) {
        try {
            Certificate certificate = Certificate.getInstance(csCert);
            SubjectPublicKeyInfo subjectPublicKeyInfo = certificate.getSubjectPublicKeyInfo();
            DERBitString publicKeyData = subjectPublicKeyInfo.getPublicKeyData();
            byte[] publicKey = publicKeyData.getEncoded();
            byte[] encodedPublicKey = publicKey;
            byte[] eP = new byte[64];
            System.arraycopy(encodedPublicKey, 4, eP, 0, eP.length);
            return eP;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
}
