package com.cryptopals.aes;

import java.util.Arrays;
import java.util.Random;

import com.cryptopals.utils.Base64Converter;
import com.cryptopals.utils.HexUtils;

public class AESUtils {
	
	public static boolean detectECB(byte[] ciphertext)
	{
		byte[][] data = new byte[ciphertext.length / 16][16];
		int pos = 0;
		for(int j=0; j<ciphertext.length/16; j++)
		{
			for(int l=0; l<16; l++)
				data[j][l] = ciphertext[pos++];
		}
		boolean ecb = false;
		for(int i=0; i<data.length; i++) {
			if(ecb) break;
			for(int j=0; j<data.length; j++) {
				if(i == j) continue;
				if(Arrays.equals(data[i], data[j])) {
					ecb = true;
					break;
				}		
			}
		}
		return ecb;
	}
	
	public static byte[] getBlock(byte[] data, int size, int block)
	{
		byte[] ret = new byte[size];
		for(int i=0; i<size; i++)
		{
			ret[i] = data[block * size + i];
		}
		return ret;
	}

}
