package com.cryptopals.sets;

import java.util.Arrays;
import java.util.Random;

import com.cryptopals.aes.*;
import com.cryptopals.utils.*;

public class Set2
{

	public static void challenge9() throws Exception
	{
		byte[] padded = AESPadding.padPKCS7("Hello World".getBytes());
		System.out.println(HexUtils.toHexStr(padded));
		System.out.println(HexUtils.toNormalStr(padded));
	}

	public static void challenge10() throws Exception
	{
		AESKey k = new AESKey("YELLOW SUBMARINE".getBytes());
		byte[] iv = new byte[16]; // gives us all nulls
		AESBlockCipher cipher = new AESBlockCipher(k, AESBlockCipher.BLOCK_MODE_CBC);
		byte[] data = FileUtils.readBase64("resources/set2_challenge10.txt");
		cipher.setIV(iv);
		cipher.decrypt(data);
		
		// stripping the pkcs7 isn't required for another couple challenges but its nicer here
		System.out.println("Plaintext: " + HexUtils.toNormalStr(data));
	}

	public static void challenge11() throws Exception
	{
		// we control the plaintext so we can force it to something that we KNOW
		// will cause ECB to
		// repeat blocks even with the padding at the front and back.
		byte[] inputText = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
		// this will give us at least 2 blocks that will be identical if its ECB

		byte[] ciphertext = BlackBox.challenge11(inputText);
		System.out.println(HexUtils.toPrettyHexStr(ciphertext));

		boolean ecb = AESUtils.detectECB(ciphertext);
		System.out.println("We think that it was done using " + (ecb ? "ECB" : "CBC"));
	}

	// we put the secret inside our 'black box' AESUtils
	public static void challenge12() throws Exception
	{
		// detect block size
		byte[] plaintext = { 0x20, 0x20 };
		byte[] ciphertext = BlackBox.challenge12(plaintext);
		byte[] block1 = ArrayUtils.copy(ciphertext, 0, ciphertext.length / 2);
		byte[] block2 = ArrayUtils.copy(ciphertext, ciphertext.length / 2, ciphertext.length - 1);
		int blocksize = 1;
		while (!Arrays.equals(block1, block2))
		{
			blocksize++;
			plaintext = ArrayUtils.fill((byte)0x20, blocksize * 2);
			ciphertext = BlackBox.challenge12(plaintext);
			block1 = ArrayUtils.copy(ciphertext, 0, blocksize);
			block2 = ArrayUtils.copy(ciphertext, blocksize, 2 * blocksize);
			if (blocksize > 128)
			{
				blocksize = -1;
				break;
			}
		}

		System.out.println("Detected blocksize is " + blocksize);

		// same as above. detect ecb
		byte[] inputText = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };

		boolean ecb = AESUtils.detectECB(BlackBox.challenge12(inputText));
		System.out.println("We think that it was done using " + (ecb ? "ECB" : "CBC"));

		// just for the record: I understand how this works for the first block,
		// but I have no idea how the heck it cascades over into the next block.
		byte[] decoded = new byte[138 + 2]; // secret is 138 bytes long
		for (int i = 0; i < 138 + 2; i++) // oh also for some reason it grabs
											// the first byte as 0xFE (the
											// padding)
		{
			int blockNum = i / blocksize;
			int blockEnd = (blockNum + 1) * blocksize;

			byte[] forcetext = ArrayUtils.fill((byte)0xFF, (blockEnd - i));
			byte[] forcedcrypto = BlackBox.challenge12(forcetext);
			byte[] block = AESUtils.getBlock(forcedcrypto, 16, blockNum);
			for (int j = 0; j < 256; j++)
			{
				byte[] testtex = ArrayUtils.fill((byte)0xFF, blocksize * (blockNum + 1));
				ArrayUtils.copy(testtex, decoded, blockEnd - i - 1, i);
				testtex[testtex.length - 1] = (byte)j;
				testtex = AESUtils.getBlock(BlackBox.challenge12(testtex), 16, blockNum);
				if (Arrays.equals(block, testtex))
				{
					decoded[i] = (byte)j;
					break;
				}
			}
		}
		byte[] secretDecoded = ArrayUtils.copy(decoded, 1, 139);
		System.out.println("Secret is: " + HexUtils.toNormalStr(secretDecoded));
	}

	public static String challenge13_profile_for(String s)
	{
		KeyValueList list = new KeyValueList();
		s = s.replace('&', '_');
		s = s.replace('=', '_');
		list.add("email", s);
		list.add("uid", "" + new Random().nextInt(50));
		list.add("role", "user");
		return list.encode();
	}

	public static void challenge13() throws Exception
	{
		String profile = challenge13_profile_for("aaaaaaaaaaadmin" + ((char)11) + ((char)11) + ((char)11) + ((char)11) + ((char)11) + ((char)11) + ((char)11) + ((char)11) + ((char)11) + ((char)11) + ((char)11) + "com");
		AESKey k = AESKey.getRandomKey();
		AESBlockCipher ci = new AESBlockCipher(k, AESBlockCipher.BLOCK_MODE_ECB);
		byte[] profileBytes = profile.getBytes();
		profileBytes = AESPadding.padPKCS7(profileBytes);
		ci.encrypt(profileBytes);

		// have fun here
		// swap block 2 and block 4
		for (int i = 0; i < 16; i++)
		{
			byte tmp = profileBytes[16 + i];
			profileBytes[16 + i] = profileBytes[48 + i];
			profileBytes[48 + i] = tmp;
		}

		ci.decrypt(profileBytes);
		KeyValueList profileObj = new KeyValueList(HexUtils.toNormalStr(profileBytes));
		System.out.println("User's role is: " + profileObj.getValue("role"));
	}

	public static void challenge14()
	{
		// we need to find which block our injected data takes over fully
		int len = 1;
		byte[] plaintext = ArrayUtils.fill((byte)0xFF, len);
		byte[] ciphertext = BlackBox.challenge14(plaintext);
		int numBlocks = ciphertext.length / 16;
		int useableBlock = -1;
		while (useableBlock == -1)
		{
			plaintext = ArrayUtils.fill((byte)0xFF, len);
			ciphertext = BlackBox.challenge14(plaintext);
			for (int i = 0; i < numBlocks - 1; i++)
			{
				byte[] block1 = ArrayUtils.copy(ciphertext, i * 16, (i + 1) * 16);
				byte[] block2 = ArrayUtils.copy(ciphertext, (i + 1) * 16, (i + 2) * 16);
				if (Arrays.equals(block1, block2))
				{
					useableBlock = i;
					break;
				}
			}
			len++;
		}

		int start = len - 33;
		System.out.println(start + " bytes before we control data");
		System.out.println("this occurs in block " + useableBlock);

		// just for the record: I understand how this works for the first block,
		// but I have no idea how the heck it cascades over into the next block.
		byte[] decoded = new byte[138 + 2]; // secret is 138 bytes long
		for (int i = 0; i < 138 + 2; i++) // oh also for some reason it grabs
											// the first byte as 0xFE (the
											// padding)
		{
			int blockNum = i / 16;
			int blockEnd = (blockNum + 1) * 16;

			byte[] forcetext = ArrayUtils.fill((byte)0xFF, start + (blockEnd - i));
			byte[] forcedcrypto = BlackBox.challenge14(forcetext);
			byte[] block = AESUtils.getBlock(forcedcrypto, 16, useableBlock + blockNum);
			for (int j = 0; j < 256; j++)
			{
				byte[] testtex = ArrayUtils.fill((byte)0xFF, start + blockEnd);
				ArrayUtils.copy(testtex, decoded, start + blockEnd - i - 1, i);
				testtex[testtex.length - 1] = (byte)j;
				testtex = AESUtils.getBlock(BlackBox.challenge14(testtex), 16, useableBlock + blockNum);
				if (Arrays.equals(block, testtex))
				{
					decoded[i] = (byte)j;
					break;
				}
			}
		}
		byte[] secretDecoded = ArrayUtils.copy(decoded, 1, 139);
		System.out.println("Secret is: " + HexUtils.toNormalStr(secretDecoded));
	}

	public static void challenge15()
	{
		byte[] padded = AESPadding.padPKCS7("Hello World!".getBytes());
		try
		{
			AESPadding.stripPKCS7(padded);
			System.out.println("Successfully removed PKCS#7 padding");
		} catch (EncryptionException e)
		{
			System.out.println("Error removing PKCS#7 padding!");
			e.printStackTrace();
		}
	}
	
	public static void challenge16() throws Exception
	{
		byte[] attackerBytes = BlackBox.challenge16_encrypt("PWNED:admin<true");
		
		byte[] block = AESUtils.getBlock(attackerBytes, 16, 1);
		block[5] = (byte)(block[5] ^ 0x1); // fix semi colon
		block[11] = (byte)(block[11] ^ 0x1); // fix equals sign
		
		AESUtils.setBlock(attackerBytes, block, 16, 1);
		
		System.out.println("admin is " + (BlackBox.challenge16_verify(attackerBytes) ? "true" : "false"));
	}

	public static void main(String[] args) throws Exception
	{ // yay just throw exceptions at hotspot!
		HexUtils.setCharset();
		System.out.println("Cryptopals Set 2 by TheApdayo");
		System.out.println("Challenge 9----------------------------------------"); 
		challenge9();
		System.out.println("Challenge 10----------------------------------------");
		challenge10();
		System.out.println("Challenge 11----------------------------------------");
		challenge11();
		System.out.println("Challenge 12----------------------------------------");
		challenge12();
		System.out.println("Challenge 13----------------------------------------");
		challenge13();
		System.out.println("Challenge 14----------------------------------------");
		challenge14();
		System.out.println("Challenge 15----------------------------------------");
		challenge15();
		System.out.println("Challenge 16----------------------------------------");
		challenge16();

	}

}
