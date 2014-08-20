package com.cryptopals.aes;

import java.security.SecureRandom;
import java.util.*;

import com.cryptopals.simpleciphers.XorCipher;
import com.cryptopals.utils.ArrayUtils;
import com.cryptopals.utils.HexUtils;

import static com.cryptopals.aes.AESUtils.*;

public class AESCipher
{

	public static final int BLOCK_MODE_ECB = 0;
	public static final int BLOCK_MODE_CBC = 1;
	public static final int BLOCK_MODE_CTR = 2;

	public static final int CIPHER_MODE_ENCRYPT = 0;
	public static final int CIPHER_MODE_DECRYPT = 1;
	public static final int CIPHER_MODE_STREAM = 2;

	public static final int PADDING_NONE = 0;
	public static final int PADDING_PKCS7 = 1;

	AESKey key;
	byte[] blocks;
	byte[] result;

	byte[] iv;
	byte[] nonce = new byte[8];
	long streamCounter = 0;
	LinkedList<Byte> streamKeyBytes = new LinkedList<Byte>();

	int initialLength;

	int cipherMode, blockMode, paddingMode;

	private String curRound = "";

	/**
	 * Create an AES cipher in the specified mode, block mode, and padding
	 */
	public AESCipher(AESKey k, int ciMode, int blMode, int pad)
	{
		key = k;
		cipherMode = ciMode;
		blockMode = blMode;
		paddingMode = pad;
	}

	/**
	 * Create an AES cipher in the specified mode and block mode with no padding
	 */
	public AESCipher(AESKey k, int ciMode, int blMode)
	{
		key = k;
		cipherMode = ciMode;
		blockMode = blMode;
		paddingMode = PADDING_NONE;
	}

	/**
	 * Create an AES cipher in the specified mode with ECB and no padding
	 */
	public AESCipher(AESKey k, int ci)
	{
		key = k;
		cipherMode = ci;
		blockMode = BLOCK_MODE_ECB;
		paddingMode = PADDING_NONE;
	}

	/**
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
		case CIPHER_MODE_STREAM:
			streamMode();
			break;
		}
	}

	private void streamMode()
	{
		for(int i=0; i<blocks.length; i++)
		{
			if(streamKeyBytes.isEmpty()) getStreamKeyBytes();
			result[i] = (byte)(blocks[i] ^ streamKeyBytes.removeFirst());
		}
	}
	
	private void getStreamKeyBytes()
	{
		byte[] back1 = blocks; // make backup of data
		byte[] back2 = result;
		
		blocks = new byte[16];
		result = new byte[16];
		blocks[0] = nonce[0];
		blocks[1] = nonce[1];
		blocks[2] = nonce[2];
		blocks[3] = nonce[3];
		blocks[4] = nonce[4];
		blocks[5] = nonce[5];
		blocks[6] = nonce[6];
		blocks[7] = nonce[7];
		blocks[8] = (byte)((streamCounter >> 0) & 0xFF);
		blocks[9] = (byte)((streamCounter >> 8) & 0xFF);
		blocks[10] = (byte)((streamCounter >> 16) & 0xFF);
		blocks[11] = (byte)((streamCounter >> 24) & 0xFF);
		blocks[12] = (byte)((streamCounter >> 32) & 0xFF);
		blocks[13] = (byte)((streamCounter >> 40) & 0xFF);
		blocks[14] = (byte)((streamCounter >> 48) & 0xFF);
		blocks[15] = (byte)((streamCounter >> 56) & 0xFF);
		streamCounter++;
		encrypt();
		for(int i=0; i<16; i++)
			streamKeyBytes.addLast(result[i]);
		
		// restore data
		blocks = back1;
		result = back2;
	}

	/**
	 * Internally run the encryption function
	 */
	private void encrypt()
	{
		for (int j = 0; j < (blocks.length / 16) + 1; j++)
		{
			byte[] b = null;
			try
			{
				b = getBlock(blocks, 16, j, paddingMode != PADDING_NONE);
			} catch (EncryptionException e)
			{
				break;
			}
			if (b == null)
				continue;
			byte[] tmp = null;
			// System.out.print("Plain: " + HexUtils.toNormalStr(b.getData()));
			if (blockMode == BLOCK_MODE_CBC)
			{
				if (j == 0) // us IV
					b = XorCipher.fixed(iv, b);
				else b = XorCipher.fixed(getBlock(result, 16, j - 1), b);
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
			setBlock(result, b, 16, j);
			// System.out.println(curRound);
			// System.out.println(" Crypto: " + HexUtils.toHexStr(b.getData()));
		}
	}

	/**
	 * Internally run the decryption function
	 */
	private void decrypt()
	{
		// we go backwards so cbc works properly
		for (int j = (blocks.length / 16) - 1; j >= 0; j--)
		{
			byte[] b = getBlock(blocks, 16, j);
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
					b = XorCipher.fixed(iv, b);
				else b = XorCipher.fixed(getBlock(blocks, 16, j - 1), b);
			}

			setBlock(result, b, 16, j);
			// System.out.println(curRound);
			// System.out.println(" Plain: " + HexUtils.toNormalStr(b.getData()));
		}
	}

	/**
	 * Provide data for the cipher
	 */
	public void initData(byte[] data)
	{
		blocks = data;
		int roundUp = data.length + 16 - 1 - (data.length - 1) % 16;
		int paddingBytes = (data.length % 16 == 0 && cipherMode == CIPHER_MODE_ENCRYPT) ? 16 : 0;
		if (cipherMode == CIPHER_MODE_STREAM)
			result = new byte[data.length];
		else result = new byte[roundUp + paddingBytes];
	}

	/**
	 * Set the Initialization Vector for CBC mode
	 */
	public void setIV(byte[] data)
	{
		if (data.length != 16)
			throw new EncryptionException("IV must be same as block size! (128 bits)");
		iv = data;
	}

	public void setNonce(byte[] n)
	{
		if(n.length != 8)
			throw new EncryptionException("Nonce must be 8 bytes long!");
		nonce = n;
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
	private void addRoundKey(byte[] b, int round)
	{
		curRound = "AddRoundKey(" + round + ", " + curRound + ")";
		byte[] roundkey = key.getRoundKey(round);
		for (int i = 0; i < 16; i++)
		{
			b[i] = (byte)(b[i] ^ roundkey[i]);
		}
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

	/**
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

	/**
	 * Internal function for AES
	 */
	private void shiftRow(byte[] b)
	{
		curRound = "ShiftRow(" + curRound + ")";
		// we skip row 0
		setRow(b, 1, rotate(getRow(b, 1)));
		setRow(b, 2, rotate(rotate(getRow(b, 2))));
		setRow(b, 3, rotate(rotate(rotate(getRow(b, 3)))));
	}

	/**
	 * Internal function for AES
	 */
	private void invShiftRow(byte[] b)
	{
		curRound = "InvShiftRow(" + curRound + ")";
		// we skip row 0
		setRow(b, 1, invRotate(getRow(b, 1)));
		setRow(b, 2, invRotate(invRotate(getRow(b, 2))));
		setRow(b, 3, invRotate(invRotate(invRotate(getRow(b, 3)))));
	}

	/**
	 * Internal function for AES
	 */
	private void subBytes(byte[] b)
	{
		curRound = "SubBytes(" + curRound + ")";
		for (int i = 0; i < 16; i++)
		{
			b[i] = AESLookup.forwardBox(b[i]);
		}
	}

	/**
	 * Internal function for AES
	 */
	private void invSubBytes(byte[] b)
	{
		curRound = "InvSubBytes(" + curRound + ")";
		for (int i = 0; i < 16; i++)
		{
			b[i] = AESLookup.inverseBox(b[i]);
		}
	}

	/**
	 * Internal function for AES
	 */
	private void mixColumns(byte[] b)
	{
		curRound = "MixColumns(" + curRound + ")";
		byte[][] s = new byte[4][4];
		s[0] = getRow(b, 0);
		s[1] = getRow(b, 1);
		s[2] = getRow(b, 2);
		s[3] = getRow(b, 3);
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
		setRow(b, 0, s[0]);
		setRow(b, 1, s[1]);
		setRow(b, 2, s[2]);
		setRow(b, 3, s[3]);
	}

	/**
	 * Internal function for AES
	 */
	private void invMixColumns(byte[] b)
	{
		curRound = "InvMixColumns(" + curRound + ")";
		byte[][] s = new byte[4][4];
		s[0] = getRow(b, 0);
		s[1] = getRow(b, 1);
		s[2] = getRow(b, 2);
		s[3] = getRow(b, 3);
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
		setRow(b, 0, s[0]);
		setRow(b, 1, s[1]);
		setRow(b, 2, s[2]);
		setRow(b, 3, s[3]);
	}

	/**
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

	protected byte[] getRow(byte[] b, int r)
	{
		byte[] ret = new byte[4];
		ret[0] = b[r];
		ret[1] = b[r + 4];
		ret[2] = b[r + 8];
		ret[3] = b[r + 12];
		return ret;
	}

	protected void setRow(byte[] b, int r, byte[] data)
	{
		b[r] = data[0];
		b[r + 4] = data[1];
		b[r + 8] = data[2];
		b[r + 12] = data[3];
	}

	/**
	 * Get the current state of the cipher
	 */
	public byte[] getState()
	{
		return result;
	}
}
