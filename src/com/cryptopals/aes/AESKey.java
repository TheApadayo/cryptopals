package com.cryptopals.aes;

import java.util.*;

import com.cryptopals.utils.HexUtils;

public class AESKey {
	
	protected byte[] keyData;
	protected byte[] expandedKey;
	protected int keySize;
	protected int expandedKeySize;

	/*
	 * Make an AES key with the following bytes and prepare it for use
	 */
	public AESKey(byte[] data) {
		if (data.length != 16 && data.length != 24 && data.length != 32)
			throw new EncryptionException("Invalid Key Size");
		keySize = data.length;
		keyData = data;
		expandKey();
	}

	/*
	 * Get the Round AES key for use in the crypto
	 */
	protected byte[] getRoundKey(int r)
	{
		byte[] ret = new byte[16];
		for(int i=0; i<16; i++)
			ret[i] = expandedKey[(r * 16) + i];
		return ret;
	}
	
	/*
	 * Rotate 4 bytes by one spot
	 */
	private byte[] rotate(byte[] d)
	{
		byte c = d[0];
	    for (int i = 0; i < 3; i++)
	        d[i] = d[i+1];
	    d[3] = c;
	    return d;
	}
	
	/*
	 * Core Expansion function for the key schedule
	 */
	private void expandCore(byte[] word, int iter)
	{
		if(word.length != 4) throw new EncryptionException("Key expansion error: word isnt 4 bytes!");
		word = rotate(word);
		for(int i=0; i<4; i++)
		{
			word[i] = (byte)AESLookup.forwardBox(word[i]);
		}
		word[0] = (byte)(word[0] ^ AESLookup.rcon(iter));
	}
	
	/*
	 * Expands the given key to a round key for use.
	 */
	private void expandKey()
	{
		int currentSize = keySize;
		int rconIter = 1;
		byte[] tmp = new byte[4];
		switch(keySize)
		{
		case 16: expandedKeySize = 176; break;
		case 24: expandedKeySize = 208; break;
		case 32: expandedKeySize = 240; break;
		}
		expandedKey = new byte[expandedKeySize];
		
		for(int i=0; i<keySize; i++)
			expandedKey[i] = keyData[i];
		
		while(currentSize < expandedKeySize)
		{
			// grab the most recent 4 bytes 
			for(int i=0; i<4; i++)
				tmp[i] = expandedKey[currentSize - 4 + i];
			if(currentSize % keySize == 0) // every keySize bytes do the core
				expandCore(tmp, rconIter++);
			
			// for large keys we need the extra s-box step
			if(keySize == 32 && (currentSize % keySize == 16))
			{
				for(int i=0; i<4; i++)
					tmp[i] = AESLookup.forwardBox(tmp[i]);
			}
			
			for(int i=0;i<4; i++)
			{
				expandedKey[currentSize] = (byte)(expandedKey[currentSize - keySize] ^ tmp[i]);
				currentSize++;
			}
		}
	}
	
	/*
	 * Get the number of rounds for the keysize
	 */
	protected int numRounds()
	{
		switch(keySize)
		{
		case 16: return 10;
		case 24: return 12;
		case 32: return 14;
		}
		return -1;
	}

}
