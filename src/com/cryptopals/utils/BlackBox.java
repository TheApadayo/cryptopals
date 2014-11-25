package com.cryptopals.utils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;

import com.cryptopals.aes.*;
import com.cryptopals.random.*;
import com.cryptopals.simpleciphers.*;

public class BlackBox
{

	public static byte[] challenge11(byte[] inputText)
	{
		Random r = new Random();
		AESKey k = AESKey.getRandomKey();
		int blockMode = (r.nextBoolean()) ? AESBlockCipher.BLOCK_MODE_ECB : AESBlockCipher.BLOCK_MODE_CBC;
		AESBlockCipher cipher = new AESBlockCipher(k, blockMode);
		if (blockMode == AESBlockCipher.BLOCK_MODE_CBC)
			cipher.setIV(AESUtils.generateRandomIV());

		int before = r.nextInt(5) + 5;
		int after = r.nextInt(5) + 5;
		byte[] data = new byte[inputText.length + before + after];
		r.nextBytes(data);
		for (int i = 0; i < inputText.length; i++)
		{
			data[i + before] = inputText[i];
		}
		data = AESPadding.padPKCS7(data);
		cipher.encrypt(data);
		return data;
	}

	private static AESKey challenge12_hiddenKey;

	public static byte[] challenge12(byte[] inputText)
	{
		if (challenge12_hiddenKey == null)
			challenge12_hiddenKey = AESKey.getRandomKey();
		AESBlockCipher cipher = new AESBlockCipher(challenge12_hiddenKey, AESBlockCipher.BLOCK_MODE_ECB);
		byte[] secret = Base64Converter.Base64toBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
		byte[] data = new byte[inputText.length + secret.length];
		for (int i = 0; i < inputText.length; i++)
			data[i] = inputText[i];
		for (int i = 0; i < secret.length; i++)
			data[i + inputText.length] = secret[i];
		data = AESPadding.padPKCS7(data);
		cipher.encrypt(data);
		return data;
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

		AESBlockCipher cipher = new AESBlockCipher(challenge14_hiddenKey, AESBlockCipher.BLOCK_MODE_ECB);
		byte[] secret = Base64Converter.Base64toBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

		byte[] data = new byte[challenge14_nonce.length + inputText.length + secret.length];
		for (int i = 0; i < challenge14_nonce.length; i++)
			data[i] = challenge14_nonce[i];
		for (int i = 0; i < inputText.length; i++)
			data[i + challenge14_nonce.length] = inputText[i];
		for (int i = 0; i < secret.length; i++)
			data[i + challenge14_nonce.length + inputText.length] = secret[i];
		data = AESPadding.padPKCS7(data);
		cipher.encrypt(data);
		return data;
	}

	private static AESKey challenge16_hiddenKey;
	private static byte[] challenge16_IV;

	public static byte[] challenge16_encrypt(String input) throws Exception
	{
		if (challenge16_hiddenKey == null)
			challenge16_hiddenKey = AESKey.getRandomKey();
		if (challenge16_IV == null)
			challenge16_IV = AESUtils.generateRandomIV();

		input = input.replace('=', '.').replace(';', '.');
		AESBlockCipher cipher = new AESBlockCipher(challenge16_hiddenKey, AESBlockCipher.BLOCK_MODE_CBC);
		cipher.setIV(challenge16_IV);
		
		String plain = "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon";
		byte[] data = plain.getBytes();
		
		cipher.encrypt(data);
		return data;
	}

	public static boolean challenge16_verify(byte[] cipherText)
	{
		AESBlockCipher cipher = new AESBlockCipher(challenge16_hiddenKey, AESBlockCipher.BLOCK_MODE_CBC);
		cipher.setIV(challenge16_IV);
		byte[] data = new byte[cipherText.length];
		for(int i=0; i<cipherText.length; i++)
			data[i] = cipherText[i];
		cipher.decrypt(data);
		return HexUtils.toNormalStr(data).contains(";admin=true;");
	}
	
	private static AESKey challenge17_hiddenKey;
	private static byte[] challenge17_IV;
	
	public static byte[] challenge17_encrypt()
	{
		if (challenge17_hiddenKey == null)
			challenge17_hiddenKey = AESKey.getRandomKey();
		if (challenge17_IV == null)
			challenge17_IV = AESUtils.generateRandomIV();

		String[] lines = FileUtils.readLines("resources/set3_challenge17.txt");
		byte[] data = Base64Converter.Base64toBytes(lines[new Random().nextInt(lines.length)]);
		AESBlockCipher cipher = new AESBlockCipher(challenge17_hiddenKey, AESBlockCipher.BLOCK_MODE_CBC);
		cipher.setIV(challenge17_IV);
		data = AESPadding.padPKCS7(data);
		cipher.encrypt(data);
		return data;
	}
	
	public static byte[] challenge17_IV()
	{
		return challenge17_IV;
	}
	
	public static void challenge17_consume(byte[] data)
	{
		AESBlockCipher cipher = new AESBlockCipher(challenge17_hiddenKey, AESBlockCipher.BLOCK_MODE_CBC);
		cipher.setIV(challenge17_IV);
		cipher.decrypt(data);
		AESPadding.stripPKCS7(data); // this will give us our exception
	}
	
	public static ArrayList<byte[]> challenge19()
	{
		ArrayList<byte[]> ret = new ArrayList<byte[]>();
		String[] lines = FileUtils.readLines("resources/set3_challenge19.txt");
		AESKey k = AESKey.getRandomKey();
		for(String line : lines)
		{
			byte[] data = Base64Converter.Base64toBytes(line);
			AESStreamCipher cipher = new AESStreamCipher(k);
			cipher.process(data);
			ret.add(data);
		}
		return ret;
	}
	
	public static byte[][] challenge20()
	{
		ArrayList<byte[]> ret = new ArrayList<byte[]>();
		String[] lines = FileUtils.readLines("resources/set3_challenge20.txt");
		AESKey k = AESKey.getRandomKey();
		for(String line : lines)
		{
			byte[] data = Base64Converter.Base64toBytes(line);
			AESStreamCipher cipher = new AESStreamCipher(k);
			cipher.process(data);
			ret.add(data);
		}
		byte[][] array = new byte[ret.size()][128];
		ret.toArray(array);
		return array;
	}
	
	public static int challenge22() throws Exception
	{
		Random r = new Random();
		Thread.sleep((r.nextInt(90) + 10) * 1000);
		PsuedoRandom pr = new PsuedoRandom(System.currentTimeMillis());
		Thread.sleep((r.nextInt(90) + 10) * 1000);
		return pr.nextInt();
	}
	
	public static byte[] challenge24(byte[] plain)
	{
		SecureRandom rng = new SecureRandom();
		RNGStreamCipher cipher = new RNGStreamCipher(rng.nextLong());
		byte[] data = new byte[plain.length + rng.nextInt(500)];
		rng.nextBytes(data);
		for(int i=0; i<plain.length; i++)
		{
			data[i + (data.length - plain.length)] = plain[i];
		}
		cipher.process(data);
		return data;
	}
	
	private static AESKey challenge25_key;
	
	public static byte[] challenge25()
	{
		// get the data
		byte[] data = FileUtils.readBase64("resources/set4_challenge25.txt");
		AESBlockCipher cipher = new AESBlockCipher(new AESKey("YELLOW SUBMARINE".getBytes()), AESBlockCipher.BLOCK_MODE_ECB);
		cipher.decrypt(data);
		
		// now re-encrypt it
		challenge25_key = AESKey.getRandomKey();
		AESStreamCipher strm = new AESStreamCipher(challenge25_key);
		strm.process(data);
		
		return data;
	}
	
	public static byte[] challenge25_edit(byte[] ciphertext, int offset, byte[] newplain)
	{
		AESStreamCipher strm = new AESStreamCipher(challenge25_key);
		
		byte[] data = new byte[ciphertext.length];
		ArrayUtils.copy(data, newplain, offset, newplain.length);
		strm.process(data);
		
		byte[] ret = ArrayUtils.duplicate(ciphertext);
		ArrayUtils.copy(ret, data, offset, data.length);
		
		return ret;
	}
	
	private static AESKey challenge26_hiddenKey;

	public static byte[] challenge26_encrypt(String input) throws Exception
	{
		if (challenge26_hiddenKey == null)
			challenge26_hiddenKey = AESKey.getRandomKey();

		input = input.replace('=', '.').replace(';', '.');
		AESStreamCipher cipher = new AESStreamCipher(challenge26_hiddenKey);
		
		String plain = "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon";
		byte[] data = plain.getBytes();
		
		cipher.process(data);
		return data;
	}

	public static boolean challenge26_verify(byte[] cipherText)
	{
		AESStreamCipher cipher = new AESStreamCipher(challenge26_hiddenKey);
		byte[] data = new byte[cipherText.length];
		for(int i=0; i<cipherText.length; i++)
			data[i] = cipherText[i];
		cipher.process(data);
		return HexUtils.toNormalStr(data).contains(";admin=true;");
	}
	
	private static AESKey challenge27_hiddenKey;
	public static byte[] challenge27_encrypt(byte[] data)
	{
		if(challenge27_hiddenKey == null)
			challenge27_hiddenKey = AESKey.getRandomKey();
		byte[] ret = ArrayUtils.duplicate(data);
		AESBlockCipher cipher = new AESBlockCipher(challenge27_hiddenKey, AESBlockCipher.BLOCK_MODE_CBC);
		cipher.setIV(challenge27_hiddenKey.keyBytes());
		cipher.encrypt(ret);
		return ret;
	}
	
	public static byte[] challenge27_decrypt(byte[] data) throws Exception
	{
		if(challenge27_hiddenKey == null)
			challenge27_hiddenKey = AESKey.getRandomKey();
		byte[] ret = ArrayUtils.duplicate(data);
		AESBlockCipher cipher = new AESBlockCipher(challenge27_hiddenKey, AESBlockCipher.BLOCK_MODE_CBC);
		cipher.setIV(challenge27_hiddenKey.keyBytes());
		cipher.decrypt(ret);
		HexUtils.verfiyASCII(ret); // this throws our exception
		return ret;
	}
}
