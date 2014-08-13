package com.cryptopals.set1;

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
	
	public static byte[] single(byte[] arr, byte key)
	{
		for(int i=0; i<arr.length; i++)
		{
			arr[i] ^= key;
		}
		return arr;
	}
	
	public static byte[] repeating(byte[] arr, byte[] key)
	{
		for(int i=0; i<arr.length; i++)
		{
			arr[i] = (byte)(arr[i] ^ key[i % key.length]);
		}
		return arr;
	}

}
