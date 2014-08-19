package com.cryptopals.aes;

import java.security.SecureRandom;

import com.cryptopals.simpleciphers.XorCipher;
import com.cryptopals.utils.ArrayUtils;
import com.cryptopals.utils.HexUtils;

public class AESCipher
{

	public static final int BLOCK_MODE_ECB = 0;
	public static final int BLOCK_MODE_CBC = 1;

	public static final int CIPHER_MODE_ENCRYPT = 0;
	public static final int CIPHER_MODE_DECRYPT = 1;

	public static final int PADDING_NONE = 0;
	public static final int PADDING_PKCS7 = 1;

	AESKey key;
	AESBlock[] blocks;

	AESBlock iv;

	int initialLength;

	int cipherMode, blockMode, paddingMode;

	private String curRound = "";

	/*
	 * Create an AES cipher for use with the following key and settings
	 */
	public AESCipher(AESKey k, int ciMode, int blMode, int pad)
	{
		key = k;
		cipherMode = ciMode;
		blockMode = blMode;
		paddingMode = pad;
	}

	/*
	 * Run the Cipher
	 */
	public void run()
	{
		if (blockMode == BLOCK_MODE_CBC && iv == null)
			throw new EncryptionException("Cannot run cipher in CBC mode without IV!");
		switch (cipherMode)
		{
		case CIPHER_MODE_ENCRYPT:
			encrypt();
			break;
		case CIPHER_MODE_DECRYPT:
			decrypt();
			break;
		}
	}

	/*
	 * Internally run the encryption function
	 */
	private void encrypt()
	{
		for (int j = 0; j < blocks.length; j++)
		{
			AESBlock b = blocks[j];
			if(b == null) continue;
			// System.out.print("Plain: " + HexUtils.toNormalStr(b.getData()));
			if (blockMode == BLOCK_MODE_CBC)
			{
				if (j == 0) // us IV
					b.setData(XorCipher.fixed(iv.getData(), b.getData()));
				else
					b.setData(XorCipher.fixed(blocks[j - 1].getData(), b.getData()));
			}
			int rndKey = 0;
			curRound = "state";
			addRoundKey(b, rndKey++);
			// System.out.println(curRound);
			for (int i = 0; i < key.numRounds() - 1; i++)
			{
				curRound = "state";
				subBytes(b);
				shiftRow(b);
				mixColumns(b);
				addRoundKey(b, rndKey++);
				// System.out.println(curRound);
			}
			curRound = "state";
			subBytes(b);
			shiftRow(b);
			addRoundKey(b, rndKey++);
			// System.out.println(curRound);
			// System.out.println(" Crypto: " + HexUtils.toHexStr(b.getData()));
		}
	}

	/*
	 * Internally run the decryption function
	 */
	private void decrypt()
	{
		// we go backwards so cbc works properly
		for (int j = blocks.length - 1; j >= 0; j--)
		{
			AESBlock b = blocks[j];
			// System.out.print("Crypto: " + HexUtils.toHexStr(b.getData()));
			int rndKey = key.numRounds();
			curRound = "state";
			addRoundKey(b, rndKey--);
			// System.out.println(curRound);
			for (int i = 0; i < key.numRounds() - 1; i++)
			{
				curRound = "state";
				invShiftRow(b);
				invSubBytes(b);
				addRoundKey(b, rndKey--);
				invMixColumns(b);
				// System.out.println(curRound);
			}
			curRound = "state";
			invShiftRow(b);
			invSubBytes(b);
			addRoundKey(b, rndKey--);

			if (blockMode == BLOCK_MODE_CBC)
			{
				if (iv == null)
					throw new EncryptionException("Cannot run cipher in CBC mode without IV!");
				if (j == 0) // us IV
					b.setData(XorCipher.fixed(iv.getData(), b.getData()));
				else
					b.setData(XorCipher.fixed(blocks[j - 1].getData(), b.getData()));
			}

			// System.out.println(curRound);
			// System.out.println(" Plain: " + HexUtils.toNormalStr(b.getData()));
		}
	}

	/*
	 * Provide data for the cipher
	 */
	public void initData(byte[] data)
	{
		int extraBlocks = ((data.length % 16 != 0) ? 1 : 0);
		blocks = new AESBlock[data.length / 16 + ((paddingMode != PADDING_NONE) ? extraBlocks : 0)];
		initialLength = data.length;
		int pos = 0;
		for (int i = 0; i < data.length / 16; i++)
		{
			byte[] blockdata = new byte[16];
			for (int j = 0; j < 16; j++)
				blockdata[j] = data[pos++];
			blocks[i] = new AESBlock(blockdata);
		}
		// grab the last block of data and do padding here if we need to
		if (paddingMode == PADDING_PKCS7 && cipherMode == CIPHER_MODE_ENCRYPT)
		{
			if (data.length % 16 != 0)
			{
				byte[] blockdata = new byte[16];
				int j = 0;
				while (pos < data.length)
					blockdata[j++] = data[pos++];

				byte pad = (byte)(16 - j);
				while (j < 16)
					blockdata[j++] = pad;
				blocks[blocks.length - 1] = new AESBlock(blockdata);
			} else
			{
				blocks[blocks.length - 1] = new AESBlock(ArrayUtils.fill((byte)16, 16));
			}
		}
	}

	/*
	 * Set the Initialization Vector for CBC mode
	 */
	public void setIV(byte[] data)
	{
		if (data.length != 16)
			throw new EncryptionException("IV must be same as block size! (128 bits)");
		iv = new AESBlock(data);
	}

	/*
	 * Generate a cryptografically secure random IV
	 */
	public static byte[] generateRandomIV()
	{
		byte[] ret = new byte[16];
		SecureRandom rng = new SecureRandom();
		rng.nextBytes(ret);
		return ret;
	}

	/*
	 * Internal function for AES
	 */
	private void addRoundKey(AESBlock b, int round)
	{
		curRound = "AddRoundKey(" + round + ", " + curRound + ")";
		byte[] roundkey = key.getRoundKey(round);
		byte[] block = b.getData();
		for (int i = 0; i < 16; i++)
		{
			block[i] = (byte)(block[i] ^ roundkey[i]);
		}
		b.setData(block);
	}

	private byte[] rotate(byte[] word)
	{
		byte[] ret = new byte[word.length];
		byte tmp = word[0];
		for (int i = 0; i < word.length - 1; i++)
		{
			ret[i] = word[i + 1];
		}
		ret[word.length - 1] = tmp;
		return ret;
	}

	/*
	 * Internal function for AES
	 */
	private byte[] invRotate(byte[] word)
	{
		byte[] ret = new byte[word.length];
		byte tmp = word[word.length - 1];
		for (int i = word.length - 1; i > 0; i--)
		{
			ret[i] = word[i - 1];
		}
		ret[0] = tmp;
		return ret;
	}

	/*
	 * Internal function for AES
	 */
	private void shiftRow(AESBlock b)
	{
		curRound = "ShiftRow(" + curRound + ")";
		// we skip row 0
		b.setRow(1, rotate(b.getRow(1)));
		b.setRow(2, rotate(rotate(b.getRow(2))));
		b.setRow(3, rotate(rotate(rotate(b.getRow(3)))));
	}

	/*
	 * Internal function for AES
	 */
	private void invShiftRow(AESBlock b)
	{
		curRound = "InvShiftRow(" + curRound + ")";
		// we skip row 0
		b.setRow(1, invRotate(b.getRow(1)));
		b.setRow(2, invRotate(invRotate(b.getRow(2))));
		b.setRow(3, invRotate(invRotate(invRotate(b.getRow(3)))));
	}

	/*
	 * Internal function for AES
	 */
	private void subBytes(AESBlock b)
	{
		curRound = "SubBytes(" + curRound + ")";
		byte[] data = b.getData();
		for (int i = 0; i < 16; i++)
		{
			data[i] = AESLookup.forwardBox(data[i]);
		}
		b.setData(data);
	}

	/*
	 * Internal function for AES
	 */
	private void invSubBytes(AESBlock b)
	{
		curRound = "InvSubBytes(" + curRound + ")";
		byte[] data = b.getData();
		for (int i = 0; i < 16; i++)
		{
			data[i] = AESLookup.inverseBox(data[i]);
		}
		b.setData(data);
	}

	/*
	 * Internal function for AES
	 */
	private void mixColumns(AESBlock b)
	{
		curRound = "MixColumns(" + curRound + ")";
		byte[][] s = new byte[4][4];
		s[0] = b.getRow(0);
		s[1] = b.getRow(1);
		s[2] = b.getRow(2);
		s[3] = b.getRow(3);
		int[] sp = new int[4];
		for (int c = 0; c < 4; c++)
		{
			sp[0] = FFMul((byte)0x02, s[0][c]) ^ FFMul((byte)0x03, s[1][c]) ^ s[2][c] ^ s[3][c];
			sp[1] = s[0][c] ^ FFMul((byte)0x02, s[1][c]) ^ FFMul((byte)0x03, s[2][c]) ^ s[3][c];
			sp[2] = s[0][c] ^ s[1][c] ^ FFMul((byte)0x02, s[2][c]) ^ FFMul((byte)0x03, s[3][c]);
			sp[3] = FFMul((byte)0x03, s[0][c]) ^ s[1][c] ^ s[2][c] ^ FFMul((byte)0x02, s[3][c]);
			for (int i = 0; i < 4; i++)
				s[i][c] = (byte)(sp[i]);
		}
		b.setRow(0, s[0]);
		b.setRow(1, s[1]);
		b.setRow(2, s[2]);
		b.setRow(3, s[3]);
	}

	/*
	 * Internal function for AES
	 */
	private void invMixColumns(AESBlock b)
	{
		curRound = "InvMixColumns(" + curRound + ")";
		byte[][] s = new byte[4][4];
		s[0] = b.getRow(0);
		s[1] = b.getRow(1);
		s[2] = b.getRow(2);
		s[3] = b.getRow(3);
		int[] sp = new int[4];
		for (int c = 0; c < 4; c++)
		{
			sp[0] = FFMul((byte)0x0e, s[0][c]) ^ FFMul((byte)0x0b, s[1][c]) ^ FFMul((byte)0x0d, s[2][c]) ^ FFMul((byte)0x09, s[3][c]);
			sp[1] = FFMul((byte)0x09, s[0][c]) ^ FFMul((byte)0x0e, s[1][c]) ^ FFMul((byte)0x0b, s[2][c]) ^ FFMul((byte)0x0d, s[3][c]);
			sp[2] = FFMul((byte)0x0d, s[0][c]) ^ FFMul((byte)0x09, s[1][c]) ^ FFMul((byte)0x0e, s[2][c]) ^ FFMul((byte)0x0b, s[3][c]);
			sp[3] = FFMul((byte)0x0b, s[0][c]) ^ FFMul((byte)0x0d, s[1][c]) ^ FFMul((byte)0x09, s[2][c]) ^ FFMul((byte)0x0e, s[3][c]);
			for (int i = 0; i < 4; i++)
				s[i][c] = (byte)(sp[i]);
		}
		b.setRow(0, s[0]);
		b.setRow(1, s[1]);
		b.setRow(2, s[2]);
		b.setRow(3, s[3]);
	}

	/*
	 * Internal function for AES
	 */
	private byte FFMul(byte a, byte b)
	{
		byte aa = a, bb = b, r = 0, t;
		while (aa != 0)
		{
			if ((aa & 1) != 0)
				r = (byte)(r ^ bb);
			t = (byte)(bb & 0x80);
			bb = (byte)(bb << 1);
			if (t != 0)
				bb = (byte)(bb ^ 0x1b);
			aa = (byte)((aa & 0xff) >> 1);
		}
		return r;
	}

	/*
	 * Get the current state of the cipher
	 */
	public byte[] getResult()
	{
		byte[] ret = new byte[blocks.length * 16];
		int pos = 0;
		for (AESBlock b : blocks)
		{
			byte[] block = b.getData();
			for (int i = 0; i < 16; i += 1)
			{
				ret[pos++] = block[i];
			}
		}
		return ret;
	}

	public static byte[] stripPKCS7(byte[] arr)
	{
		if (arr[arr.length - 1] < 0 || arr[arr.length - 1] > 16)
			throw new EncryptionException("Invalid PKCS#7 padding!");
		return ArrayUtils.copy(arr, 0, arr.length - arr[arr.length - 1]);
	}
}
