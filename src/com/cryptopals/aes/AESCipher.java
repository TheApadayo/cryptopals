package com.cryptopals.aes;

import java.util.*;

public class AESCipher
{

	public static final int BLOCKSIZE = 16;

	AESKey key;

	long streamCounter = 0;
	LinkedList<Byte> streamKeyBytes = new LinkedList<Byte>();

	int initialLength;

	private String curRound = "";
	
	public AESCipher(AESKey k)
	{
		if(k == null) throw new EncryptionException("Can't create cipher without a key!");
		key = k;
	}

	/**
	 * Encrypt one block of data
	 */
	
	protected void encryptBlock(byte[] b)
	{
		int rndKey = 0;
		addRoundKey(b, rndKey++);
		for (int i = 0; i < key.numRounds() - 1; i++)
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

	/**
	 * Decrypt one block of data
	 */
	protected void decryptBlock(byte[] b)
	{
		int rndKey = key.numRounds();
		addRoundKey(b, rndKey--);
		for (int i = 0; i < key.numRounds() - 1; i++)
		{
			invShiftRow(b);
			invSubBytes(b);
			addRoundKey(b, rndKey--);
			invMixColumns(b);
		}
		invShiftRow(b);
		invSubBytes(b);
		addRoundKey(b, rndKey--);
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
}
