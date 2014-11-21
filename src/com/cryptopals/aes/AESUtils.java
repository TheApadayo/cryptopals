package com.cryptopals.aes;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import com.cryptopals.utils.ArrayUtils;
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
		return getBlock(data, size, block, false);
	}
	
	public static byte[] getBlock(byte[] data, int size, int block, boolean pad)
	{
		byte[] ret = new byte[size];
		int padByte = 0;
		for(int i=0; i<size; i++)
		{
			if(block * size + i < data.length)
				ret[i] = data[block * size + i];
			else if(pad) { if(padByte == 0) padByte = size - i;
				ret[i] = (byte)padByte;
			} else throw new EncryptionException("Trying to get non existant block!");
		}
		return ret;
	}
	
	public static void setBlock(byte[] cipher, byte[] data, int size, int block)
	{
		if(cipher.length < (block+1) * size) throw new EncryptionException("Trying to set a non existant block!");
		for(int i=0; i<data.length; i++)
		{
			cipher[i + (block * data.length)] = data[i];
		}
	}
	
	/**
	 * Generate a cryptografically secure random IV
	 */
	public static byte[] generateRandomIV()
	{
		byte[] ret = new byte[16];
		SecureRandom rng = new SecureRandom();
		rng.nextBytes(ret);
		return ret;
	}

}
