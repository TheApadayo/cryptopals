package com.cryptopals.sets;

import com.cryptopals.simpleciphers.*;
import com.cryptopals.utils.*;
import com.cryptopals.aes.*;
import com.cryptopals.hash.*;

public class Set4
{
	public static void challenge25()
	{
		byte[] data = BlackBox.challenge25();
		byte[] force = ArrayUtils.fill((byte)0, data.length);
		byte[] data2 = BlackBox.challenge25_edit(data, 0, force);
		
		byte[] plaintext = XorCipher.fixed(data, data2);
		System.out.println("Plaintext is: " + HexUtils.toNormalStr(plaintext));
	}
	
	public static void challenge26() throws Exception
	{
		byte[] data = BlackBox.challenge26_encrypt(":admin<true");
		data[32] ^= 0x01;
		data[38] ^= 0x01;
		System.out.println("admin=" + (BlackBox.challenge26_verify(data) ? "true" : "false"));
	}
	
	public static void challenge27() throws Exception
	{
		byte[] data = ArrayUtils.fill((byte)'A', AESCipher.BLOCKSIZE * 3);
		data = BlackBox.challenge27_encrypt(data);
		AESUtils.setBlock(data, new byte[16], 16, 1);
		AESUtils.setBlock(data, AESUtils.getBlock(data, 16, 0), 16, 2);
		// we wan't it to error so catch it here
		try
		{
			data = BlackBox.challenge27_decrypt(data);
			System.out.println(HexUtils.toPrettyHexStr(data));
		}
		catch (Exception e)
		{
			String error = e.getMessage();
			System.out.println(error);
			byte[] plaintext = HexUtils.toByteArray(error.substring(8, 104));
			byte[] b1 = AESUtils.getBlock(plaintext, 16, 0);
			byte[] b2 = AESUtils.getBlock(plaintext, 16, 2);
			byte[] key = XorCipher.fixed(b1, b2);
			System.out.println("Key is " + HexUtils.toHexStr(key));
		}
	}
	
	public static void challenge28()
	{
		System.out.println(HexUtils.toHexStr(SHA1.getHash("The quick brown fox jumps over the lazy dog".getBytes())));
	}
	
	public static void main(String[] args) throws Exception
	{ // yay just throw exceptions at hotspot!
		HexUtils.setCharset();

		System.out.println("Cryptopals Set 4 by TheApdayo");
		/*
		System.out.println("Challenge 25----------------------------------------");
		challenge25();
		System.out.println("Challenge 26----------------------------------------");
		challenge26();
		System.out.println("Challenge 27----------------------------------------");
		challenge27();
		*/
		System.out.println("Challenge 28----------------------------------------");
		challenge28();
	}

}
