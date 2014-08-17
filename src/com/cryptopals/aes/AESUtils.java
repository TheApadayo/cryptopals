package com.cryptopals.aes;

import java.util.Arrays;
import java.util.Random;

import com.cryptopals.utils.Base64Converter;

public class AESUtils {
	
	public static boolean detectECB(byte[] ciphertext)
	{
		byte[][] data = new byte[ciphertext.length / 16][16];
		int pos = 0;
		for(int j=0; j<ciphertext.length/16; j++)
		{
			for(int l=0; l<16; l++)
				data[j][l] = ciphertext[pos++];
		}
		boolean ecb = false;
		for(int i=0; i<data.length; i++) {
			if(ecb) break;
			for(int j=0; j<data.length; j++) {
				if(i == j) continue;
				if(Arrays.equals(data[i], data[j])) {
					ecb = true;
					break;
				}		
			}
		}
		return ecb;
	}
	
	public static byte[] encryptRandomly(byte[] inputText)
	{
		Random r = new Random();
		AESKey k = AESKey.getRandomKey();
		int blockMode = (r.nextBoolean()) ? AESCipher.BLOCK_MODE_ECB : AESCipher.BLOCK_MODE_CBC;
		AESCipher cipher = new AESCipher(k, AESCipher.CIPHER_MODE_ENCRYPT, blockMode, AESCipher.PADDING_PKCS7);
		if(blockMode == AESCipher.BLOCK_MODE_CBC)
			cipher.setIV(AESCipher.generateRandomIV());
		
		int before = r.nextInt(5) + 5;
		int after = r.nextInt(5) + 5;
		byte[] plaintext = new byte[inputText.length + before + after];
		r.nextBytes(plaintext);
		for(int i=0; i<inputText.length; i++)
		{
			plaintext[i + before] = inputText[i];
		}
		cipher.initData(plaintext);
		cipher.run();
		return cipher.getResult();
	}
	
	private static AESKey hiddenKey;
	
	public static byte[] encryptSecretly(byte[] inputText)
	{
		if(hiddenKey == null) hiddenKey = AESKey.getRandomKey();
		AESCipher cipher = new AESCipher(hiddenKey, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		byte[] secret = Base64Converter.Base64toBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
		byte[] plaintext = new byte[inputText.length + secret.length];
		for(int i=0; i<inputText.length; i++)
			plaintext[i] = inputText[i];
		for(int i=0; i<secret.length; i++)
			plaintext[i+inputText.length] = secret[i];
		cipher.initData(plaintext);
		cipher.run();
		return cipher.getResult();
	}

}
