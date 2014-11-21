package com.cryptopals.aes;

import com.cryptopals.utils.ArrayUtils;
import com.cryptopals.utils.HexUtils;

public class AESPadding {
	
	public static byte[] padPKCS7(byte[] d)
	{
		int blocks = (d.length / AESCipher.BLOCKSIZE) + 1;
		byte[] ret = new byte[blocks * AESCipher.BLOCKSIZE];
		for(int i=0; i<d.length; i++)
			ret[i] = d[i];
		int padding = ret.length - d.length;
		for(int i = ret.length - padding; i<ret.length; i++)
			ret[i] = (byte)padding;
		return ret;
	}
	
	public static byte[] stripPKCS7(byte[] arr)
	{
		byte pad = arr[arr.length -1];
		if (pad < 1 || pad > 16)
			throw new EncryptionException("Invalid PKCS#7 padding: " + HexUtils.toHexStr(arr));
		for(int i=0; i<pad; i++)
		{
			if(arr[arr.length - pad + i] != pad)
				throw new EncryptionException("Invalid PKCS#7 padding: " + HexUtils.toHexStr(arr));
		}
		return ArrayUtils.copy(arr, 0, arr.length - arr[arr.length - 1]);
	}

}
