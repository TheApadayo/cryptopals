package com.cryptopals.set1;

public class Base64Converter {

	private static String indexTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
	private static char mapTo(int i)
	{
		return indexTable.charAt(i);
	}
	
	private static int mapFrom(char c)
	{
		if(c == '=') return 0;
		return indexTable.indexOf(c);
	}

	public static String BytestoBase64(byte[] bytes) {
		String ret = "";

		// do our main sequence of encoding 3 bytes to 4 chars
		int i = 0;
		for (; i < bytes.length - 2; i += 3) {
			int j = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
			ret += mapTo((j >> 18) & 0x3F);
			ret += mapTo((j >> 12) & 0x3F);
			ret += mapTo((j >> 6) & 0x3F);
			ret += mapTo(j & 0x3F);
		}
		int pad = bytes.length % 3;
		if (pad == 2) {
			int j = bytes[i++] << 16 | bytes[i++] << 8;
			ret += mapTo((j >> 18) & 0x3F);
			ret += mapTo((j >> 12) & 0x3F);
			ret += mapTo((j >> 6) & 0x3F);
			ret += "=";
		} else if (pad == 1) {
			int j = bytes[i++] << 16;
			ret += mapTo((j >> 18) & 0x3F);
			ret += mapTo((j >> 12) & 0x3F);
			ret += "==";

		}
		return ret;
	}

	public static byte[] Base64toBytes(String str) {
		byte [] ret = new byte[(int)(str.length() * 0.75)];
		int pos = 0;
		for(int i=0; i<str.length(); i+=4){
			int j = (mapFrom(str.charAt(i)) << 18) | 
					(mapFrom(str.charAt(i + 1)) << 12) |
					(mapFrom(str.charAt(i + 2)) << 6) |
					(mapFrom(str.charAt(i + 3)));
			ret[pos++] = (byte)((j >> 16) & 0xFF);
			ret[pos++] = (byte)((j >> 8) & 0xFF);
			ret[pos++] = (byte)(j & 0xFF);
		}
		
		return ret;
	}

}
