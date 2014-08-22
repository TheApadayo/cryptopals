package com.cryptopals.simpleciphers;

import com.cryptopals.utils.HexUtils;

public class XorCipher {
	
	public static byte[] fixed(byte[] b1, byte[] b2) {
		if(b1.length != b2.length) throw new RuntimeException("arrays must be same length");
		byte[] ret = new byte[b1.length];
		for(int i=0; i<b1.length; i++)
		{
			ret[i] = (byte) (b1[i] ^ b2[i]);
		}
		return ret;
	}
	
	public static byte[] fixed(byte[] b1, byte[] b2, int len)
	{
		if(len > b1.length || len > b2.length)
			throw new RuntimeException("Cant do fixed xor longer than buffers");
		byte[] ret = new byte[len];
		for(int i=0; i<len; i++)
		{
			ret[i] = (byte) (b1[i] ^ b2[i]);
		}
		return ret;
	}
	
	public static byte[] single(byte[] arr, byte key)
	{
		byte[] ret = new byte[arr.length];
		for(int i=0; i<arr.length; i++)
		{
			ret[i] = (byte) (arr[i] ^ key);
		}
		return ret;
	}
	
	public static byte[] repeating(byte[] arr, byte[] key)
	{
		byte[] ret = new byte[arr.length];
		for(int i=0; i<arr.length; i++)
		{
			ret[i] = (byte)(arr[i] ^ key[i % key.length]);
		}
		return ret;
	}

}
