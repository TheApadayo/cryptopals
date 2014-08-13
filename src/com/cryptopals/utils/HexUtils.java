package com.cryptopals.utils;

import java.io.UnsupportedEncodingException;

public class HexUtils {
	
	private static int getHexChar(char hex) {
		// i hate ascii so I'm just gona steal this
		if ('0' <= hex && hex <= '9') {
			return hex - '0';
		}

		if (hex >= 'A' && hex <= 'Z') {
			return hex - 'A' + 10;
		}

		return hex - 'a' + 10;
	}

	public static byte[] toByteArray(String str) {
		if (str.length() % 2 != 0)
			return null;
		byte[] ret = new byte[str.length() / 2];
		for (int i = 0; i < str.length(); i += 2) {
			ret[i / 2] = (byte) ((getHexChar(str.charAt(i)) << 4) | getHexChar(str
					.charAt(i + 1)));
		}
		return ret;
	}
	
	private static String hexKey = "0123456789abcdef";
	public static String toHexStr(byte[] arr) {
		String s = "";
		for(byte b : arr)
		{
			s += hexKey.charAt((b & 0xF0) >> 4);
			s += hexKey.charAt(b & 0x0F);
		}
		return s;
	}
	
	public static String toNormalStr(byte[] arr)
	{
		try {
		return new String(arr, "UTF-8");
		} catch (Exception e) {
			return "";
		}
	}
	
	public static double stringMetric(byte[] arr)
	{
		int count = 0;
		for(byte b : arr)
		{
			// find a better metric
			if( (b >= 'a' && b <= 'z') || b >= 'A' && b <= 'Z' || // chars
					b == ' ' || b == '\'' || b == '.' || b == '!' || b == '?' ||  // punctuaion 
					b == '\n' || b == '\t' || b == '\r') // escape chars
				count++;
		}
		return (double) count / arr.length;
	}
	
	private static int countBits(byte b)
	{
		int i = 0;
		if((b & 0x01) != 0) i++;
		if((b & 0x02) != 0) i++;
		if((b & 0x04) != 0) i++;
		if((b & 0x08) != 0) i++;
		if((b & 0x10) != 0) i++;
		if((b & 0x20) != 0) i++;
		if((b & 0x40) != 0) i++;
		if((b & 0x80) != 0) i++;
		return i;
	}
	
	public static int HammingDistance(byte[] s1, byte[] s2)
	{
		if(s1.length != s2.length) return -1;
		int dist = 0;
		for(int i=0; i<s1.length; i++)
		{
			dist += countBits((byte) (s1[i] ^ s2[i]));
		}
		return dist;
	}

}
