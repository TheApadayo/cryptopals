package com.cryptopals.sets;

import java.security.SecureRandom;

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
		System.out.println(HexUtils.toNormalStr(AESUtils.stripPKCS7(plaintext)));
	}
	
	public static void challenge18()
	{
		AESKey k = new AESKey("YELLOW SUBMARINE".getBytes());
		AESCipher c = new AESCipher(k, AESCipher.CIPHER_MODE_STREAM);
		c.initData(Base64Converter.Base64toBytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="));
		c.run();
		System.out.println(HexUtils.toNormalStr(c.getState()));
	}

	public static void main(String[] args) throws Exception
	{ // yay just throw exceptions at hotspot!
		HexUtils.setCharset();
		System.out.println("Cryptopals Set 3 by TheApdayo");
		System.out.println("Challenge 17----------------------------------------");
		challenge17();
		System.out.println("Challenge 18----------------------------------------");
		challenge18();
	}

}
