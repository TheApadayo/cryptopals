package com.cryptopals.aes;

import com.cryptopals.utils.HexUtils;

public class AESCipher {
	
	public static final int BLOCK_MODE_ECB = 0;
	public static final int BLOCK_MODE_CBC = 1;
	
	public static final int CIPHER_MODE_ENCRYPT = 0;
	public static final int CIPHER_MODE_DECRYPT = 1;
	
	public static final int PADDING_NONE = 0;
	
	AESKey key;
	AESBlock[] blocks;
	
	int initialLength;
	
	int cipherMode, blockMode, paddingMode;
	
	
	public AESCipher(AESKey k, int ciMode, int blMode, int pad)
	{
		key = k;
		cipherMode = ciMode;
		blockMode = blMode;
		paddingMode = pad;
	}
	
	public void run()
	{
		switch(cipherMode) {
		case CIPHER_MODE_ENCRYPT: encrypt(); break;
		case CIPHER_MODE_DECRYPT: decrypt(); break;
		}
	}
	
	private void encrypt()
	{
		for(AESBlock b : blocks) {
			int rndKey = 0;
			addRoundKey(b, rndKey++);
			for(int i=0; i<key.numRounds()-1; i++)
			{
				subBytes(b);
				shiftRow(b);
				mixColumns(b);
				addRoundKey(b, rndKey++);
			}
			subBytes(b);
			shiftRow(b);
			addRoundKey(b, rndKey++);
		}
	}
	
	private void decrypt()
	{
		
	}
	
	public void initData(byte[] data)
	{
		blocks = new AESBlock[data.length/16];
		initialLength = data.length;
		int pos = 0;
		for(int i=0; i<data.length/16; i++)
		{
			byte[] blockdata = new byte[16];
			for(int j=0; j<16; j++)
				blockdata[j] = data[pos++];
			blocks[i] = new AESBlock(blockdata);
		}
		System.out.println(HexUtils.toNormalStr(getResult()));
	}
	
	private void addRoundKey(AESBlock b, int round)
	{
		byte[] roundkey = key.getRoundKey(round);
		byte[] block = b.getData();
		for(int i=0; i<16; i++)
		{
			block[i] = (byte) (block[i] ^ roundkey[i]);
		}
		b.setData(block);
	}
	
	private void shiftRow(AESBlock b)
	{
		byte[] tmp = new byte[4];
		// we skip row 0
		byte[] row = b.getRow(1);
		tmp[0] = row[1];
		tmp[1] = row[2];
		tmp[2] = row[3];
		tmp[3] = row[0];
		b.setRow(1, tmp);
		row = b.getRow(2);
		tmp[0] = row[2];
		tmp[1] = row[3];
		tmp[2] = row[0];
		tmp[3] = row[1];
		b.setRow(1, tmp);
		row = b.getRow(3);
		tmp[0] = row[3];
		tmp[1] = row[0];
		tmp[2] = row[1];
		tmp[3] = row[2];
		b.setRow(1, tmp);
	}
	
	private void subBytes(AESBlock b)
	{
		byte[] data = b.getData();
		for(int i=0; i<16; i++)
		{
			data[i] = RSALookup.forwardBox(data[i]);
		}
		b.setData(data);
	}
	
	private void mixColumns(AESBlock b)
	{
		byte[] block = b.getData();
		for(int i=0; i<16; i+=4)
		{
			block[i  ] = (byte)((block[i] * 2) ^ (block[i+1] * 3) ^ (block[i+2] * 1) ^ (block[i+3] * 1));
			block[i+1] = (byte)((block[i] * 1) ^ (block[i+1] * 2) ^ (block[i+2] * 3) ^ (block[i+3] * 1));
			block[i+2] = (byte)((block[i] * 1) ^ (block[i+1] * 1) ^ (block[i+2] * 2) ^ (block[i+3] * 3));
			block[i+3] = (byte)((block[i] * 3) ^ (block[i+1] * 1) ^ (block[i+2] * 1) ^ (block[i+3] * 2));
		}
		b.setData(block);
	}
	
	public byte[] getResult()
	{
		byte[] ret = new byte[initialLength];
		int pos = 0;
		for(AESBlock b : blocks)
		{
			byte[] block = b.getData();
			for(int i=0; i<16; i+=1)
			{
				ret[pos++] = block[i];
				if(pos == initialLength) break;
			}
		}
		return ret;
	}
}
