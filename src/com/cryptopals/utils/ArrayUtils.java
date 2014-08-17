package com.cryptopals.utils;

public class ArrayUtils {
	
	public static byte[] copy(byte[] input, int start, int end)
	{
		byte[] ret = new byte[end - start];
		for(int i=0; i<ret.length; i++)
		{
			ret[i] = input[start + i];
		}
		return ret;
	}
	
	public static byte[] fill(byte b, int count)
	{
		byte[] ret = new byte[count];
		for(int i=0; i<count; i++)
		{
			ret[i] = b;
		}
		return ret;
	}
	
	public static void copy(byte[] dest, byte[] input, int destOff, int len)
	{
		for(int i=0; i<len; i++)
		{
			dest[destOff + i] = input[i];
		}
	}
}
