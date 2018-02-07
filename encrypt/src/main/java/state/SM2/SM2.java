package state.SM2;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import state.common.Cipher;

import org.bouncycastle.math.ec.ECFieldElement.Fp;

import util.Util;

public class SM2 {
	
	

	public String encrypt(String pub, String data) {
		try {
			return encrypt(Util.hexStringToBytes(pub), Util.hexStringToBytes(data));
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	// 国密推荐参数
	private static String[] ecc_param = { "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
			"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
			"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
			"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" };

	private static SM2 Instance() {
		return new SM2();
	}

	private final BigInteger ecc_p;
	private final BigInteger ecc_a;
	private final BigInteger ecc_b;
	private final BigInteger ecc_n;
	private final BigInteger ecc_gx;
	private final BigInteger ecc_gy;
	private final ECCurve ecc_curve;
	private final ECPoint ecc_point_g;
	private final ECDomainParameters ecc_bc_spec;
	private final ECKeyPairGenerator ecc_key_pair_generator;
	private final ECFieldElement ecc_gx_fieldelement;
	private final ECFieldElement ecc_gy_fieldelement;
	
	private SM2() {
		this.ecc_p = new BigInteger(ecc_param[0], 16);
		this.ecc_a = new BigInteger(ecc_param[1], 16);
		this.ecc_b = new BigInteger(ecc_param[2], 16);
		this.ecc_n = new BigInteger(ecc_param[3], 16);
		this.ecc_gx = new BigInteger(ecc_param[4], 16);
		this.ecc_gy = new BigInteger(ecc_param[5], 16);

		this.ecc_gx_fieldelement = new Fp(this.ecc_p, this.ecc_gx);
		this.ecc_gy_fieldelement = new Fp(this.ecc_p, this.ecc_gy);

		this.ecc_curve = new ECCurve.Fp(this.ecc_p, this.ecc_a, this.ecc_b);
		this.ecc_point_g = new ECPoint.Fp(this.ecc_curve, this.ecc_gx_fieldelement, this.ecc_gy_fieldelement);

		this.ecc_bc_spec = new ECDomainParameters(this.ecc_curve, this.ecc_point_g, this.ecc_n);

		ECKeyGenerationParameters ecc_ecgenparam;
		ecc_ecgenparam = new ECKeyGenerationParameters(this.ecc_bc_spec, new SecureRandom());

		this.ecc_key_pair_generator = new ECKeyPairGenerator();
		this.ecc_key_pair_generator.init(ecc_ecgenparam);
	}

	// 生成随机秘钥对
	private String[] generateKeyPair() {
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();
		return new String[] { Util.byteToHex(publicKey.getEncoded()), Util.byteToHex(privateKey.toByteArray()) };
	}

	// 数据加密
	private String encrypt(byte[] privateKey, byte[] data) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (data == null || data.length == 0) {
			return null;
		}else{
			
		}

		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);

		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(privateKey);

		ECPoint c1 = Init_enc(sm2, userKey);
		Cipher cipher=new Cipher();
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);

	}

	// 数据解密
	private byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}

		String data = Util.byteToHex(encryptedData);

		byte[] c1Bytes = Util.hexToByte(data.substring(0, 130));
		int c2Len = encryptedData.length - 97;
		byte[] c2 = Util.hexToByte(data.substring(130, 130 + 2 * c2Len));
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));

		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);

		// 通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);

		// 返回解密结果
		return c2;
	}
	public ECPoint Init_enc(SM2 sm2, ECPoint userKey)   
	  {  
	      AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();  
	      ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();  
	      ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();  
	      BigInteger k = ecpriv.getD();  
	      ECPoint c1 = ecpub.getQ();  
	      userKey.multiply(k);  
	      return c1;  
	  }  
}