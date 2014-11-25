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
	
	public static byte[] duplicate(byte[] input)
	{
		return copy(input, 0, input.length);
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
	
	public static byte[] resize(byte[] src, int newsize)
	{
		byte [] ret = new byte[newsize];
		for(int i=0; i<src.length; i++)
			ret[i] = src[i];
		return ret;
	}
}
