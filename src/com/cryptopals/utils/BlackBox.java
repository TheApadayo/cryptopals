package com.cryptopals.utils;

import java.security.SecureRandom;
import java.util.Random;

import com.cryptopals.aes.AESCipher;
import com.cryptopals.aes.AESKey;
import com.cryptopals.aes.AESUtils;

public class BlackBox
{

	public static byte[] challenge11(byte[] inputText)
	{
		Random r = new Random();
		AESKey k = AESKey.getRandomKey();
		int blockMode = (r.nextBoolean()) ? AESCipher.BLOCK_MODE_ECB : AESCipher.BLOCK_MODE_CBC;
		AESCipher cipher = new AESCipher(k, AESCipher.CIPHER_MODE_ENCRYPT, blockMode, AESCipher.PADDING_PKCS7);
		if (blockMode == AESCipher.BLOCK_MODE_CBC)
			cipher.setIV(AESCipher.generateRandomIV());

		int before = r.nextInt(5) + 5;
		int after = r.nextInt(5) + 5;
		byte[] plaintext = new byte[inputText.length + before + after];
		r.nextBytes(plaintext);
		for (int i = 0; i < inputText.length; i++)
		{
			plaintext[i + before] = inputText[i];
		}
		cipher.initData(plaintext);
		cipher.run();
		return cipher.getState();
	}

	private static AESKey challenge12_hiddenKey;

	public static byte[] challenge12(byte[] inputText)
	{
		if (challenge12_hiddenKey == null)
			challenge12_hiddenKey = AESKey.getRandomKey();
		AESCipher cipher = new AESCipher(challenge12_hiddenKey, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		byte[] secret = Base64Converter.Base64toBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
		byte[] plaintext = new byte[inputText.length + secret.length];
		for (int i = 0; i < inputText.length; i++)
			plaintext[i] = inputText[i];
		for (int i = 0; i < secret.length; i++)
			plaintext[i + inputText.length] = secret[i];
		cipher.initData(plaintext);
		cipher.run();
		return cipher.getState();
	}

	private static AESKey challenge14_hiddenKey;
	private static byte[] challenge14_nonce;

	public static byte[] challenge14(byte[] inputText)
	{
		if (challenge14_hiddenKey == null)
			challenge14_hiddenKey = AESKey.getRandomKey();
		if (challenge14_nonce == null)
		{
			SecureRandom r = new SecureRandom();
			challenge14_nonce = new byte[r.nextInt(64) + 16];
			r.nextBytes(challenge14_nonce);
		}

		AESCipher cipher = new AESCipher(challenge14_hiddenKey, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		byte[] secret = Base64Converter.Base64toBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

		byte[] plaintext = new byte[challenge14_nonce.length + inputText.length + secret.length];
		for (int i = 0; i < challenge14_nonce.length; i++)
			plaintext[i] = challenge14_nonce[i];
		for (int i = 0; i < inputText.length; i++)
			plaintext[i + challenge14_nonce.length] = inputText[i];
		for (int i = 0; i < secret.length; i++)
			plaintext[i + challenge14_nonce.length + inputText.length] = secret[i];
		cipher.initData(plaintext);
		cipher.run();
		return cipher.getState();
	}

	private static AESKey challenge16_hiddenKey;
	private static byte[] challenge16_IV;

	public static byte[] challenge16_encrypt(String input) throws Exception
	{
		if (challenge16_hiddenKey == null)
			challenge16_hiddenKey = AESKey.getRandomKey();
		if (challenge16_IV == null)
			challenge16_IV = AESCipher.generateRandomIV();

		input = input.replace('=', '.').replace(';', '.');
		AESCipher cipher = new AESCipher(challenge16_hiddenKey, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_CBC, AESCipher.PADDING_PKCS7);
		String plain = "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon";
		cipher.initData(plain.getBytes("UTF-8"));
		cipher.setIV(challenge16_IV);
		cipher.run();
		return cipher.getState();
	}

	public static boolean challenge16_verify(byte[] cipherText)
	{
		AESCipher cipher = new AESCipher(challenge16_hiddenKey, AESCipher.CIPHER_MODE_DECRYPT, AESCipher.BLOCK_MODE_CBC, AESCipher.PADDING_PKCS7);
		cipher.initData(cipherText);
		cipher.setIV(challenge16_IV);
		cipher.run();
		return HexUtils.toNormalStr(cipher.getState()).contains(";admin=true;");
	}
	
	private static AESKey challenge17_hiddenKey;
	private static byte[] challenge17_IV;
	
	public static byte[] challenge17_encrypt()
	{
		if (challenge17_hiddenKey == null)
			challenge17_hiddenKey = AESKey.getRandomKey();
		if (challenge17_IV == null)
			challenge17_IV = AESCipher.generateRandomIV();

		String[] lines = FileUtils.readLines("resources/set3_challenge17.txt");
		byte[] input = Base64Converter.Base64toBytes(lines[new Random().nextInt(lines.length)]);
		AESCipher cipher = new AESCipher(challenge17_hiddenKey, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_CBC, AESCipher.PADDING_PKCS7);
		cipher.initData(input);
		cipher.setIV(challenge17_IV);
		cipher.run();
		return cipher.getState();
	}
	
	public static byte[] challenge17_IV()
	{
		return challenge17_IV;
	}
	
	public static void challenge17_consume(byte[] data)
	{
		AESCipher cipher = new AESCipher(challenge17_hiddenKey, AESCipher.CIPHER_MODE_DECRYPT, AESCipher.BLOCK_MODE_CBC, AESCipher.PADDING_PKCS7);
		cipher.initData(data);
		cipher.setIV(challenge17_IV);
		cipher.run();
		AESUtils.stripPKCS7(cipher.getState()); // this will give us our exception
	}
}
