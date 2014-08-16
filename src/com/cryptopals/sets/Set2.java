package com.cryptopals.sets;

import com.cryptopals.aes.*;
import com.cryptopals.utils.*;

public class Set2 {
	
	public static void challenge9() throws Exception
	{
		AESKey k = new AESKey("YELLOW SUBMARINE".getBytes("UTF-8"));
		AESCipher cipher = new AESCipher(k, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		cipher.initData(FileUtils.readFull("resources/lipsum.txt").getBytes("UTF-8"));
		cipher.run();
		System.out.println("Ciphertext: " + HexUtils.toHexStr(cipher.getResult()));
		
		AESCipher cipher2 = new AESCipher(k, AESCipher.CIPHER_MODE_DECRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		cipher2.initData(cipher.getResult());
		cipher2.run();
		System.out.println("Plaintext: " + HexUtils.toNormalStr(cipher2.getResult()));
	}
	
	public static void challenge10() throws Exception
	{
		AESKey k = new AESKey("YELLOW SUBMARINE".getBytes("UTF-8"));
		byte[] iv = new byte[16]; // gives us all nulls
		AESCipher cipher = new AESCipher(k, AESCipher.CIPHER_MODE_DECRYPT, AESCipher.BLOCK_MODE_CBC, AESCipher.PADDING_PKCS7);
		cipher.initData(FileUtils.readBase64("resources/set2_challenge10.txt"));
		cipher.setIV(iv);
		cipher.run();
		System.out.println("Plaintext: " + HexUtils.toNormalStr(cipher.getResult()));
	}

	public static void main(String[] args) throws Exception { // yay just throw exceptions at hotspot!
		
		challenge9();
		System.out.println("----------------------------------------");
		challenge10();
	}

}
