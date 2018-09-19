package com.hzy.library;

import android.util.Log;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;


/**
 * Created by ziye_huang on 2018/9/19.
 */
public class SM2Util {
    private static String TAG = SM2Util.class.getSimpleName();

    @SuppressWarnings("deprecation")
    public static byte[] encrypt(byte[] publicKey, byte[] data) {
        if (publicKey == null || publicKey.length == 0) {
            return null;
        }

        if (data == null || data.length == 0) {
            return null;
        }

        byte[] source = new byte[data.length];
        System.arraycopy(data, 0, source, 0, data.length);

        byte[] formatedPubKey;
        if (publicKey.length == 64) {
            // 添加一字节标识，用于ECPoint解析
            formatedPubKey = new byte[65];
            formatedPubKey[0] = 0x04;
            System.arraycopy(publicKey, 0, formatedPubKey, 1, publicKey.length);
        } else
            formatedPubKey = publicKey;

        Cipher cipher = new Cipher();
        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(formatedPubKey);

        ECPoint c1 = cipher.Init_enc(sm2, userKey);
        cipher.Encrypt(source);
        byte[] c3 = new byte[32];
        cipher.Dofinal(c3);

        ASN1Integer x = new ASN1Integer(c1.getX().toBigInteger());
        ASN1Integer y = new ASN1Integer(c1.getY().toBigInteger());
        DEROctetString derDig = new DEROctetString(c3);
        DEROctetString derEnc = new DEROctetString(source);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(x);
        v.add(y);
        v.add(derDig);
        v.add(derEnc);
        DERSequence seq = new DERSequence(v);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DEROutputStream dos = new DEROutputStream(bos);
        try {
            dos.writeObject(seq);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) {
        if (privateKey == null || privateKey.length == 0) {
            return null;
        }

        if (encryptedData == null || encryptedData.length == 0) {
            return null;
        }

        byte[] enc = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0, enc, 0, encryptedData.length);

        SM2 sm2 = SM2.Instance();
        BigInteger userD = new BigInteger(1, privateKey);

        ByteArrayInputStream bis = new ByteArrayInputStream(enc);
        ASN1InputStream dis = new ASN1InputStream(bis);
        try {
            ASN1Primitive derObj = dis.readObject();
            ASN1Sequence asn1 = (ASN1Sequence) derObj;
            ASN1Integer x = (ASN1Integer) asn1.getObjectAt(0);
            ASN1Integer y = (ASN1Integer) asn1.getObjectAt(1);
            ECPoint c1 = sm2.ecc_curve.createPoint(x.getValue(), y.getValue(), true);

            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            DEROctetString data = (DEROctetString) asn1.getObjectAt(3);
            enc = data.getOctets();
            cipher.Decrypt(enc);
            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);
            return enc;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            try {
                dis.close();
            } catch (IOException e) {
            }
        }
    }

    /**
     * 使用默认ID计算
     *
     * @param privateKey
     * @param sourceData
     * @return
     * @throws IOException
     */
    public static byte[] sign(byte[] privateKey, byte[] sourceData) throws IOException {
        String userId = "1234567812345678";
        return sign(userId.getBytes(), privateKey, sourceData);
    }

    @SuppressWarnings("deprecation")
    public static byte[] sign(byte[] userId, byte[] privateKey, byte[] sourceData) throws IOException {
        if (privateKey == null || privateKey.length == 0) {
            return null;
        }

        if (sourceData == null || sourceData.length == 0) {
            return null;
        }

        SM2 sm2 = SM2.Instance();
        BigInteger userD = new BigInteger(privateKey);
        Log.e(TAG, "userD: " + userD.toString(16));
        Log.e(TAG, "");

        ECPoint userKey = sm2.ecc_point_g.multiply(userD);
        Log.e(TAG, "椭圆曲线点X: " + userKey.getX().toBigInteger().toString(16));
        Log.e(TAG, "椭圆曲线点Y: " + userKey.getY().toBigInteger().toString(16));
        Log.e(TAG, "");

        SM3Digest sm3 = new SM3Digest();
        byte[] z = sm2.sm2GetZ(userId, userKey);
        Log.e(TAG, "SM3摘要Z: " + ByteUtil.getHexString(z));
        Log.e(TAG, "");

        Log.e(TAG, "M: " + ByteUtil.getHexString(sourceData));
        Log.e(TAG, "");

        sm3.update(z, 0, z.length);
        sm3.update(sourceData, 0, sourceData.length);
        byte[] md = new byte[32];
        sm3.doFinal(md, 0);

        Log.e(TAG, "SM3摘要值: " + ByteUtil.getHexString(md));
        Log.e(TAG, "");

        SM2Result sm2Result = new SM2Result();
        sm2.sm2Sign(md, userD, userKey, sm2Result);
        Log.e(TAG, "r: " + sm2Result.r.toString(16));
        Log.e(TAG, "s: " + sm2Result.s.toString(16));
        Log.e(TAG, "");

        ASN1Integer d_r = new ASN1Integer(sm2Result.r);
        ASN1Integer d_s = new ASN1Integer(sm2Result.s);

        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(d_r);
        v2.add(d_s);
        DERSequence sign = new DERSequence(v2);
        return sign.getEncoded();
    }

    /**
     * 使用默认id计算
     *
     * @param publicKey
     * @param sourceData
     * @param signData
     * @return
     */
    public static boolean verifySign(byte[] publicKey, byte[] sourceData, byte[] signData) {
        String userId = "1234567812345678";
        return verifySign(userId.getBytes(), publicKey, sourceData, signData);
    }

    public static boolean verifyHash(byte[] publicKey, byte[] md, byte[] signData) {
        String userId = "1234567812345678";
        return verifyHash(userId.getBytes(), publicKey, md, signData);
    }

    @SuppressWarnings("unchecked")
    public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData) {
        if (publicKey == null || publicKey.length == 0) {
            return false;
        }

        if (sourceData == null || sourceData.length == 0) {
            return false;
        }

        byte[] formatedPubKey;
        if (publicKey.length == 64) {
            // 添加一字节标识，用于ECPoint解析
            formatedPubKey = new byte[65];
            formatedPubKey[0] = 0x04;
            System.arraycopy(publicKey, 0, formatedPubKey, 1, publicKey.length);
        } else
            formatedPubKey = publicKey;

        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(formatedPubKey);

        SM3Digest sm3 = new SM3Digest();
        byte[] z = sm2.sm2GetZ(userId, userKey);
        sm3.update(z, 0, z.length);
        sm3.update(sourceData, 0, sourceData.length);
        byte[] md = new byte[32];
        sm3.doFinal(md, 0);
        Log.e(TAG, "SM3摘要值: " + ByteUtil.getHexString(md));
        Log.e(TAG, "");

        ByteArrayInputStream bis = new ByteArrayInputStream(signData);
        ASN1InputStream dis = new ASN1InputStream(bis);
        SM2Result sm2Result = null;
        try {
            ASN1Primitive derObj = dis.readObject();
            Enumeration<ASN1Integer> e = ((ASN1Sequence) derObj).getObjects();
            BigInteger r = ((ASN1Integer) e.nextElement()).getValue();
            BigInteger s = ((ASN1Integer) e.nextElement()).getValue();
            sm2Result = new SM2Result();
            sm2Result.r = r;
            sm2Result.s = s;
            Log.e(TAG, "r: " + sm2Result.r.toString(16));
            Log.e(TAG, "s: " + sm2Result.s.toString(16));
            Log.e(TAG, "");
            sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
            return sm2Result.r.equals(sm2Result.R);
        } catch (IOException e1) {
            //TODO ZJCA目前的实现模式
            byte[] rbs = new byte[64];
            byte[] sbs = new byte[64];
            System.arraycopy(signData, 0, rbs, 0, rbs.length);
            System.arraycopy(signData, 64, sbs, 0, sbs.length);
            BigInteger r = new BigInteger(rbs);
            BigInteger s = new BigInteger(sbs);
            sm2Result = new SM2Result();
            sm2Result.r = r;
            sm2Result.s = s;
            Log.e(TAG, "r: " + sm2Result.r.toString(16));
            Log.e(TAG, "s: " + sm2Result.s.toString(16));
            Log.e(TAG, "");
            sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
            return sm2Result.r.equals(sm2Result.R);
        } finally {
            try {
                dis.close();
            } catch (IOException e) {
            }
        }
    }

    public static boolean verifyHash(byte[] userId, byte[] publicKey, byte[] md, byte[] signData) {
        if (publicKey == null || publicKey.length == 0) {
            return false;
        }

        if (md == null || md.length != 32) {
            return false;
        }

        byte[] formatedPubKey;
        if (publicKey.length == 64) {
            // 添加一字节标识，用于ECPoint解析
            formatedPubKey = new byte[65];
            formatedPubKey[0] = 0x04;
            System.arraycopy(publicKey, 0, formatedPubKey, 1, publicKey.length);
        } else
            formatedPubKey = publicKey;

        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(formatedPubKey);


        ByteArrayInputStream bis = new ByteArrayInputStream(signData);
        ASN1InputStream dis = new ASN1InputStream(bis);
        SM2Result sm2Result = null;
        try {
            ASN1Primitive derObj = dis.readObject();
            Enumeration<ASN1Integer> e = ((ASN1Sequence) derObj).getObjects();
            BigInteger r = ((ASN1Integer) e.nextElement()).getValue();
            BigInteger s = ((ASN1Integer) e.nextElement()).getValue();
            sm2Result = new SM2Result();
            sm2Result.r = r;
            sm2Result.s = s;
            Log.e(TAG, "r: " + sm2Result.r.toString(16));
            Log.e(TAG, "s: " + sm2Result.s.toString(16));
            Log.e(TAG, "");
            sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
            return sm2Result.r.equals(sm2Result.R);
        } catch (IOException e1) {
            //TODO ZJCA目前的实现模式
            byte[] rbs = new byte[64];
            byte[] sbs = new byte[64];
            System.arraycopy(signData, 0, rbs, 0, rbs.length);
            System.arraycopy(signData, 64, sbs, 0, sbs.length);
            BigInteger r = new BigInteger(rbs);
            BigInteger s = new BigInteger(sbs);
            sm2Result = new SM2Result();
            sm2Result.r = r;
            sm2Result.s = s;
            Log.e(TAG, "r: " + sm2Result.r.toString(16));
            Log.e(TAG, "s: " + sm2Result.s.toString(16));
            Log.e(TAG, "");
            sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
            return sm2Result.r.equals(sm2Result.R);
        } finally {
            try {
                dis.close();
            } catch (IOException e) {
            }
        }
    }

    public static void main(String[] args) throws Exception {
        String publickey = "RYYPxf7lUNg/cH09FcYFHaPx5mAXRMcWGJMNl+a2RDx86UENCI07FhupTLMJ4ANktZV4hO8TZbv16Q0plqNpKQ==";
        String plaintext = "111";
        // 签名
        String sign = "MEUCIB5Y4LHCE40di9sZZ5LkcmyT7eRQ85Q2sx3p22Iwct2NAiEAw28BvuoIJ8zuP5D3BsQHyGZV5hMnqoi10ZI9HyPlQ2E=";
        byte[] pk = Base64.decode(publickey);

        boolean b = SM2Util.verifySign(pk, plaintext.getBytes(), Base64.decode(sign));
        int a = 0;

    }

    @SuppressWarnings("deprecation")
    public static Sm2KeyPair generateKeyPair() {
        SM2 sm2 = SM2.Instance();
        AsymmetricCipherKeyPair keypair = sm2.ecc_key_pair_generator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.getPublic();

        byte[] priKey = new byte[32];
        byte[] pubKey = new byte[64];

        byte[] bigNumArray = ecpriv.getD().toByteArray();
        System.arraycopy(bigNumArray, bigNumArray[0] == 0 ? 1 : 0, priKey, 0, 32);
        System.arraycopy(ecpub.getQ().getEncoded(), 1, pubKey, 0, 64);

        return new Sm2KeyPair(priKey, pubKey);
    }

    public static void Sm2Test() throws IOException {
        String plainText = "Hello SM !";
        byte[] sourceData = plainText.getBytes();
        Sm2KeyPair keyPair = generateKeyPair();

        Log.e(TAG, "私钥: " + ByteUtil.getHexString(keyPair.getPriKey()));
        Log.e(TAG, "公钥: " + ByteUtil.getHexString(keyPair.getPubKey()));

        byte[] c = SM2Util.sign(keyPair.getPriKey(), sourceData);
        Log.e(TAG, "sign: " + ByteUtil.getHexString(c));

        boolean vs = SM2Util.verifySign(keyPair.getPubKey(), sourceData, c);
        Log.e(TAG, "验签结果: " + vs);

        Log.e(TAG, "加密: ");
        byte[] cipherText = SM2Util.encrypt(keyPair.getPubKey(), sourceData);
        Log.e(TAG, ByteUtil.getHexString(cipherText));

        Log.e(TAG, "解密: ");
        plainText = new String(SM2Util.decrypt(keyPair.getPriKey(), cipherText));
        Log.e(TAG, plainText);
    }
}
