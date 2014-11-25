package com.cryptopals.hash;

import com.cryptopals.utils.*;

public class SHA1
{

	public static final int BLOCKSIZE = 64;
	public static final int DIGESTSIZE = 20;

	public static byte[] getHash(byte[] message)
	{
		byte[] data = padMessage(message);

		int H0 = 0x67452301;
		int H1 = 0xEFCDAB89;
		int H2 = 0x98BADCFE;
		int H3 = 0x10325476;
		int H4 = 0xC3D2E1F0;

		for (int i = 0; i < data.length / BLOCKSIZE; i++)
		{
			byte[] M = M(i, data);
			int[] W = new int[80];
			// initialize w with the data from our block
			for (int outer = 0; outer < 16; outer++) {
                int temp = 0;
                for (int inner = 0; inner < 4; inner++) {
                    temp = (M[outer * 4 + inner] & 0x000000FF) << (24 - inner * 8);
                    W[outer] = W[outer] | temp;
                }
            }
			// expand to 80 bytes
			for (int t = 16; t < 80; t++)
				W[t] = rotateLeft(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
			
			int A = H0;
			int B = H1;
			int C = H2;
			int D = H3;
			int E = H4;

			for (int t = 0; t < 80; t++)
			{
				int temp = uAdd(rotateLeft(A, 5), uAdd(f(t, B, C, D), uAdd(E, uAdd(W[t], k(t)))));
				E = D;
				D = C;
				C = rotateLeft(B, 30);
				B = A;
				A = temp;
			}
			H0 = uAdd(A, H0);
			H1 = uAdd(B, H1);
			H2 = uAdd(C, H2);
			H3 = uAdd(D, H3);
			H4 = uAdd(E, H4);
		}
		return getDigestFromHValues(new int[] { H0, H1, H2, H3, H4 });
	}

	// grab the selected block from the message
	private static byte[] M(int i, byte[] message)
	{
		byte[] ret = new byte[BLOCKSIZE];
		for (int j = 0; j < BLOCKSIZE; j++)
			ret[j] = message[i * BLOCKSIZE + j];
		return ret;
	}

	// unsigned addition operation
	private static int uAdd(int i1, int i2)
	{
		long l1 = i1 & 0xffffffffL, l2 = i2 & 0xffffffffL;
		return (int)(l1 + l2);
	}

	// rotate left operation
	private static int rotateLeft(int value, int bits)
	{
		int q = (value << bits) | (value >>> (32 - bits));
		return q;
	}

	// converts the 4 h values to a byte array digest
	private static byte[] getDigestFromHValues(int[] h)
	{
		// expands the 5 int values into a byte array
		byte[] ret = new byte[20];
		for (int i = 0; i < 5; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				int shift = (3-j) * 8;
				ret[(i * 4) + j] = (byte)(h[i] >> shift & 0xFF);
			}
		}
		return ret;
	}

	// performs the f function for the round t
	private static int f(int t, int B, int C, int D)
	{
		if (t < 20)
			return ((B & C) | ((~B) & D));
		if (t < 40)
			return (B ^ C ^ D);
		if (t < 60)
			return ((B & C) | (B & D) | (C & D));
		if (t < 80)
			return (B ^ C ^ D);
		return -1;
	}

	// returns the k constant for the current round
	private static int k(int t)
	{
		if (t <= 19)
			return 0x5A827999;
		if (t <= 39)
			return 0x6ED9EBA1;
		if (t <= 59)
			return 0x8F1BBCDC;

		return 0xCA62C1D6;
	}

	// pad the message properly
	private static byte[] padMessage(byte[] message)
	{
		byte[] ret = new byte[(message.length / BLOCKSIZE) + 1 * BLOCKSIZE];
		for (int i = 0; i < message.length; i++)
			ret[i] = message[i];
		ret[message.length] = (byte)0x80;
		// the vm fills the rest of the array with zeroes for us so we can do nothing here

		long length = message.length * 8;
		for (int i = 0; i < 8; i++)
		{
			ret[ret.length - 1 - i] = (byte)((length >> (i * 8)) & 0xFF);
		}

		return ret;
	}

}
