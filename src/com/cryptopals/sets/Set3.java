package com.cryptopals.sets;

import java.util.ArrayList;

import com.cryptopals.simpleciphers.*;
import com.cryptopals.utils.*;
import com.cryptopals.aes.*;

public class Set3
{

	public static void challenge17()
	{
		byte[] crypto = BlackBox.challenge17_encrypt();
		byte[] plaintext = new byte[crypto.length];
		byte[] iv = BlackBox.challenge17_IV();

		for (int b = (crypto.length / 16) - 1; b >= 0; b--)
		{
			byte[] plainBlock = new byte[16];
			for (int pos = 15; pos >= 0; pos--)
			{
				int padding = 16 - pos;
				// get previous block or IV in case of first block
				byte[] prevBlock = ((b == 0) ? iv : AESUtils.getBlock(crypto, 16, b - 1));
				byte[] curBlock = AESUtils.getBlock(crypto, 16, b);
				byte[] forceBlock = new byte[16];
				for (int k = 15; k > pos; k--)
				{
					// forced = plain ^ padding ^ prevBlock
					forceBlock[k] = (byte)(plainBlock[k] ^ padding ^ prevBlock[k]);
				}

				for (int j = 0; j < 256; j++)
				{
					// test the forced byte
					forceBlock[pos] = (byte)j;

					byte[] consumedData = new byte[32];
					AESUtils.setBlock(consumedData, forceBlock, 16, 0);
					AESUtils.setBlock(consumedData, curBlock, 16, 1);
					// this structure gets weird cause of the exception catching.
					// our success code goes below the consume func and failure code
					// goes in the catch block
					try
					{
						BlackBox.challenge17_consume(consumedData);
						// P = padding ^ ciphertext ^ forced
						plainBlock[pos] = (byte)(padding ^ j ^ prevBlock[pos]);

						//System.out.println("P" + b + " [" + pos + "] = " + padding + " ^ " + (prevBlock[pos] & 0xFF) + " ^ " + (j & 0xFF));
						break;
					} catch (EncryptionException e)
					{
						//System.out.println(e.getMessage());
						// j wasn't correct... continue
					}
				}
				AESUtils.setBlock(plaintext, plainBlock, 16, b); // copy to final dest
			}
		}
		System.out.println(HexUtils.toNormalStr(AESPadding.stripPKCS7(plaintext)));
	}

	public static void challenge18()
	{
		AESKey k = new AESKey("YELLOW SUBMARINE".getBytes());
		AESStreamCipher cipher = new AESStreamCipher(k);
		byte[] data = Base64Converter.Base64toBytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
		cipher.process(data);
		System.out.println(HexUtils.toNormalStr(data));
	}

	public static void challenge19()
	{
		ArrayList<byte[]> encrypted = BlackBox.challenge19();
		byte[][] decrypted = new byte[40][64];
		// ok so here we have a bunch of stuff xored against the same fixed buffer
		// so c1 ^ c2 = p1 ^ k ^ p2 ^ k = p1 ^ p2 ^ 0 = p1 ^ p2
		// therefore c1 ^ c2 = p1 ^ p2

		// so we go through here and find things that are likely spaces in our string
		for (int c = 0; c < encrypted.size(); c++)
		{
			byte[] c1 = encrypted.get(c);
			int[] spaceCounter = new int[c1.length];
			for (byte[] c2 : encrypted)
			{
				byte[] before = XorCipher.fixed(c1, c2, (c1.length < c2.length ? c1.length : c2.length));
				byte[] after = XorCipher.fixed(before, ArrayUtils.fill((byte)0x20, before.length));
				for (int i = 0; i < before.length; i++)
				{
					if (Character.isLetter(before[i]) && Character.isLetterOrDigit(after[i]))
						spaceCounter[i]++;
				}
			}
			for (int i = 0; i < spaceCounter.length; i++)
			{
				if (spaceCounter[i] > 25)
				{
					decrypted[c][i] = (byte)0x20;
				}
			}
		}

		// now we build a dict of where those spaces are
		int[] decryptDict = new int[39];
		for (int i = 0; i < 39; i++)
		{
			for (int j = 0; j < decrypted.length; j++)
			{
				if (decrypted[j][i] == (byte)0x20)
				{
					decryptDict[i] = j;
					break;
				}
				if (j == decrypted.length - 1)
				{
					decryptDict[i] = -1;
				}
			}
		}

		// finally we use our dict to simply decrypt our full string using each of the strings that have a space at each spot
		for (int c = 0; c < encrypted.size(); c++)
		{
			byte[] b = encrypted.get(c);
			for (int i = 0; i < b.length; i++)
			{
				if (decryptDict[i] == -1)
					continue;
				decrypted[c][i] = (byte)(b[i] ^ encrypted.get(decryptDict[i])[i] ^ 0x20);
			}
			System.out.println(HexUtils.toNormalStr(decrypted[c]));
		}
		// this gets us most of the way there and can be pieced together by a human
		// we could make another pass now that we know almost the entire string but we have challenge 20 for that
	}

	public static void challenge20()
	{
		byte[][] encrypted = BlackBox.challenge20();
		int len = encrypted[0].length;
		for (int i = 1; i < encrypted.length; i++)
		{
			if (encrypted[i].length < len)
				len = encrypted[i].length;
		}
		byte[][] decrypted = new byte[encrypted.length][len];
		
		System.out.println(len);

		for (int i = 0; i < len / 16; i++)
		{
			byte[][] transpose = new byte[16][16];
			for(int j=0; j<16; j++)
			{
				for(int l=0; l<16;l++)
				{
					transpose[l][j] = encrypted[j][(i * 16) + l];
				}
			}
			byte[] key = new byte[16];
			for (int k = 0; k < 16; k++)
			{
				// here we should have a buffer with every byte using the same
				// single byte xor key
				// now solve the single byte xor
				System.out.print("possible values for key pos " + k + ": ");
				for (int j = 0; j < 255; j++)
				{
					byte[] decoded = XorCipher.single(transpose[k], (byte)j);
					double score = HexUtils.stringMetric(decoded);
					if (score > 0.90) // mess with this score to get values to
										// come in and drop out.
										// anywhere from 80% to 95% works
					{
						System.out.print((int)j + ", ");
						key[k] = (byte)j;
					}
				}
				System.out.println();
			}
			System.out.println("Guessed Key: " + HexUtils.toHexStr(key));
			byte[][] result = new byte[transpose[0].length][transpose.length];
			for(int j=0; j<16; j++)
			{
				for(int l=0; l<16;l++)
				{
					result[l][j] = transpose[j][l];
				}
			}
			for(int j=0; j<result.length; j++)
			{
				result[j] = XorCipher.repeating(result[j], key);
				System.out.println(HexUtils.toNormalStr(XorCipher.repeating(result[j], key)));
			}
		}
	}

	public static void main(String[] args) throws Exception
	{ // yay just throw exceptions at hotspot!
		HexUtils.setCharset();

		System.out.println("Cryptopals Set 3 by TheApdayo");
		System.out.println("Challenge 17----------------------------------------");
		challenge17();
		System.out.println("Challenge 18----------------------------------------");
		challenge18();
		System.out.println("Challenge 19----------------------------------------");
		challenge19();
		System.out.println("Challenge 20----------------------------------------");
		challenge20();
	}

}
