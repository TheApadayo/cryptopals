package com.cryptopals.sets;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import com.cryptopals.aes.*;
import com.cryptopals.utils.*;

public class Set2
{

	public static void challenge9() throws Exception
	{
		AESKey k = new AESKey("YELLOW SUBMARINE".getBytes("UTF-8"));
		AESCipher cipher = new AESCipher(k, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		cipher.initData(FileUtils.readFull("resources/lipsum.txt").getBytes("UTF-8"));
		cipher.run();
		System.out.println("Ciphertext: " + HexUtils.toHexStr(cipher.getResult()));

		AESCipher cipher2 = new AESCipher(k, AESCipher.CIPHER_MODE_DECRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		cipher2.initData(cipher.getResult());
		cipher2.run();
		System.out.println("Plaintext: " + HexUtils.toNormalStr(cipher2.getResult()));
	}

	public static void challenge10() throws Exception
	{
		AESKey k = new AESKey("YELLOW SUBMARINE".getBytes("UTF-8"));
		byte[] iv = new byte[16]; // gives us all nulls
		AESCipher cipher = new AESCipher(k, AESCipher.CIPHER_MODE_DECRYPT, AESCipher.BLOCK_MODE_CBC, AESCipher.PADDING_PKCS7);
		cipher.initData(FileUtils.readBase64("resources/set2_challenge10.txt"));
		cipher.setIV(iv);
		cipher.run();
		System.out.println("Plaintext: " + HexUtils.toNormalStr(cipher.getResult()));
	}

	public static byte[] challenge11_encryptRandomly(byte[] inputText)
	{
		Random r = new Random();
		AESKey k = AESKey.getRandomKey();
		int blockMode = (r.nextBoolean()) ? AESCipher.BLOCK_MODE_ECB : AESCipher.BLOCK_MODE_CBC;
		AESCipher cipher = new AESCipher(k, AESCipher.CIPHER_MODE_ENCRYPT, blockMode, AESCipher.PADDING_PKCS7);
		if (blockMode == AESCipher.BLOCK_MODE_CBC)
			cipher.setIV(AESCipher.generateRandomIV());

		int before = r.nextInt(5) + 5;
		int after = r.nextInt(5) + 5;
		byte[] plaintext = new byte[inputText.length + before + after];
		r.nextBytes(plaintext);
		for (int i = 0; i < inputText.length; i++)
		{
			plaintext[i + before] = inputText[i];
		}
		cipher.initData(plaintext);
		cipher.run();
		return cipher.getResult();
	}

	public static void challenge11() throws Exception
	{
		// we control the plaintext so we can force it to something that we KNOW
		// will cause ECB to
		// repeat blocks even with the padding at the front and back.
		byte[] inputText = { 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
		// this will give us at least 2 blocks that will be identical if its ECB

		byte[] ciphertext = challenge11_encryptRandomly(inputText);
		System.out.println(HexUtils.toPrettyHexStr(ciphertext));

		boolean ecb = AESUtils.detectECB(ciphertext);
		System.out.println("We think that it was done using " + (ecb ? "ECB" : "CBC"));
	}

	private static AESKey challenge12_hiddenKey;

	public static byte[] challenge12_encryptSecretly(byte[] inputText)
	{
		if (challenge12_hiddenKey == null)
			challenge12_hiddenKey = AESKey.getRandomKey();
		AESCipher cipher = new AESCipher(challenge12_hiddenKey, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		byte[] secret = Base64Converter.Base64toBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
		byte[] plaintext = new byte[inputText.length + secret.length];
		for (int i = 0; i < inputText.length; i++)
			plaintext[i] = inputText[i];
		for (int i = 0; i < secret.length; i++)
			plaintext[i + inputText.length] = secret[i];
		cipher.initData(plaintext);
		cipher.run();
		return cipher.getResult();
	}

	// we put the secret inside our 'black box' AESUtils
	public static void challenge12() throws Exception
	{
		// detect block size
		byte[] plaintext = { 0x20, 0x20 };
		byte[] ciphertext = challenge12_encryptSecretly(plaintext);
		byte[] block1 = ArrayUtils.copy(ciphertext, 0, ciphertext.length / 2);
		byte[] block2 = ArrayUtils.copy(ciphertext, ciphertext.length / 2, ciphertext.length - 1);
		int blocksize = 1;
		while (!Arrays.equals(block1, block2))
		{
			blocksize++;
			plaintext = ArrayUtils.fill((byte)0x20, blocksize * 2);
			ciphertext = challenge12_encryptSecretly(plaintext);
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

		boolean ecb = AESUtils.detectECB(challenge12_encryptSecretly(inputText));
		System.out.println("We think that it was done using " + (ecb ? "ECB" : "CBC"));

		// just for the record: I understand how this works for the first block,
		// but I have no idea how the heck it cascades over into the next block.
		byte[] decoded = new byte[138 + 2]; // secret is 138 bytes long
		for (int i = 0; i < 138 + 2; i++) // oh also for some reason it grabs
											// the first byte as 0xFE (the
											// padding)
		{
			int blockNum = i / blocksize;
			int blockStart = blockNum * blocksize;
			int blockEnd = (blockNum + 1) * blocksize;

			byte[] forcetext = ArrayUtils.fill((byte)0xFF, (blockEnd - i));
			byte[] forcedcrypto = challenge12_encryptSecretly(forcetext);
			byte[] block = ArrayUtils.copy(forcedcrypto, blockNum * blocksize, (blockNum + 1) * blocksize);
			for (int j = 0; j < 256; j++)
			{
				byte[] testtex = ArrayUtils.fill((byte)0xFF, blocksize * (blockNum + 1));
				ArrayUtils.copy(testtex, decoded, blockEnd - i - 1, i);
				testtex[testtex.length - 1] = (byte)j;
				testtex = ArrayUtils.copy(challenge12_encryptSecretly(testtex), blockStart, blockEnd);
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
		AESCipher en = new AESCipher(k, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		AESCipher de = new AESCipher(k, AESCipher.CIPHER_MODE_DECRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		en.initData(profile.getBytes("UTF-8"));
		en.run();
		byte[] attackerBytes = en.getResult();

		// have fun here
		// swap block 2 and block 4
		for (int i = 0; i < 16; i++)
		{
			byte tmp = attackerBytes[16 + i];
			attackerBytes[16 + i] = attackerBytes[48 + i];
			attackerBytes[48 + i] = tmp;
		}

		de.initData(attackerBytes);
		de.run();
		KeyValueList profileObj = new KeyValueList(HexUtils.toNormalStr(de.getResult()));
		System.out.println("User's role is: " + profileObj.getValue("role"));
	}

	private static AESKey challenge14_hiddenKey;

	public static byte[] challenge14_encryptSecretly(byte[] inputText)
	{
		if (challenge12_hiddenKey == null)
			challenge12_hiddenKey = AESKey.getRandomKey();
		AESCipher cipher = new AESCipher(challenge12_hiddenKey, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_PKCS7);
		byte[] secret = Base64Converter.Base64toBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
		SecureRandom r = new SecureRandom();
		byte[] nonce = new byte[r.nextInt(32)];
		r.nextBytes(nonce);
		byte[] plaintext = new byte[nonce.length + inputText.length + secret.length];
		for (int i = 0; i < nonce.length; i++)
			plaintext[i] = nonce[i];
		for (int i = 0; i < inputText.length; i++)
			plaintext[i + nonce.length] = inputText[i];
		for (int i = 0; i < secret.length; i++)
			plaintext[i + nonce.length + inputText.length] = secret[i];
		cipher.initData(plaintext);
		cipher.run();
		return cipher.getResult();
	}

	public static void challenge14()
	{
		// just for the record: I understand how this works for the first block,
		// but I have no idea how the heck it cascades over into the next block.
		byte[] decoded = new byte[138 + 2]; // secret is 138 bytes long
		for (int i = 0; i < 138 + 2; i++) // oh also for some reason it grabs
											// the first byte as 0xFE (the
											// padding)
		{
			int blockNum = i / 16;
			int blockStart = blockNum * 16;
			int blockEnd = (blockNum + 1) * 16;

			byte[] forcetext = ArrayUtils.fill((byte)0xFF, (blockEnd - i));
			byte[] forcedcrypto = challenge14_encryptSecretly(forcetext);
			byte[] block = ArrayUtils.copy(forcedcrypto, blockNum * 16, (blockNum + 1) * 16);
			for (int j = 0; j < 256; j++)
			{
				byte[] testtex = ArrayUtils.fill((byte)0xFF, 16 * (blockNum + 1));
				ArrayUtils.copy(testtex, decoded, blockEnd - i - 1, i);
				testtex[testtex.length - 1] = (byte)j;
				testtex = ArrayUtils.copy(challenge12_encryptSecretly(testtex), blockStart, blockEnd);
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

	public static void main(String[] args) throws Exception
	{ // yay just throw exceptions at hotspot!
		System.out.println("Cryptopals Set 2 by TheApdayo");
		/*
		System.out.println("Challenge 9----------------------------------------"); 
		challenge9();
		System.out.println("Challenge 10----------------------------------------");
		challenge10();
		System.out.println("Challenge 11----------------------------------------");
		challenge11();
		System.out.println("Challenge 12----------------------------------------");
		challenge12();
		System.out.println("Challenge 13----------------------------------------");
		challenge13();*/
		System.out.println("Challenge 14----------------------------------------");
		challenge14();
	}

}
