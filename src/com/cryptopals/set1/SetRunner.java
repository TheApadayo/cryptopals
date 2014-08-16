package com.cryptopals.set1;

import java.io.*;
import java.util.*;

import com.cryptopals.aes.*;
import com.cryptopals.utils.*;

public class SetRunner {
	
	public static void challenge1()
	{
		// challenge 1
		byte[] c1Arr = HexUtils.toByteArray("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
		System.out.println("Should be: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");;
		System.out.println("We got:    " + Base64Converter.BytestoBase64(c1Arr));
	}
	
	public static void challenge2()
	{
		// challenge 2
		byte[] c2Xor1 = HexUtils.toByteArray("1c0111001f010100061a024b53535009181c");
		byte[] c2Xor2 = HexUtils.toByteArray("686974207468652062756c6c277320657965");
		System.out.println("Should be: 746865206b696420646f6e277420706c6179");;
		System.out.println("We got:    " + HexUtils.toHexStr(XorCipher.fixed(c2Xor1, c2Xor2)));
	}
	
	public static void challenge3()
	{
		// challenge 3
		byte[] c3Ciphertext = HexUtils.toByteArray("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
		//byte[] c3Ciphertext = HexUtils.toByteArray("196d283d28");
		System.out.println("possible decoded values for ciphertext: ");
		for(int i = 0; i < 255; i++)
		{
			byte[] decoded = XorCipher.single(c3Ciphertext, (byte)i);
			double score = HexUtils.stringMetric(decoded);
			if(score > 0.90) // at least 95% score 
				System.out.println(HexUtils.toNormalStr(decoded) + " - Score: " + score + " Key: " + (char)i);
		}
	}
	
	public static void challenge4() throws Exception
	{
		// challenge 4
		BufferedReader c4Input = new BufferedReader(new FileReader(new File("resources/set1_challenge4.txt")));
		String c4Line;
		System.out.println("possible decoded values for ciphertext: ");
		int c4LineNum = 1;
		while((c4Line = c4Input.readLine()) != null)
		{
			for(int i = 0; i < 255; i++)
			{
				byte[] decoded = XorCipher.single(HexUtils.toByteArray(c4Line), (byte)i);
				double score = HexUtils.stringMetric(decoded);
				if(score > 0.95) // at least 95% score 
					System.out.println("Line " + c4LineNum + ": " + HexUtils.toNormalStr(decoded) + " - Score: " + score + " Key: " + (char)i);
			}
			c4LineNum++;
		}
		c4Input.close();
	}
	
	public static void challenge5() throws Exception
	{
		// challenge 5
		// they tell us never to depend on encoding but since we're specifiying it here
		// it should be ok
		byte[] c4Plaintext = ("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal").getBytes("UTF-8");
		byte[] c4Key = "ICE".getBytes();
		System.out.println("Should be: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
		System.out.println("We got:    " + HexUtils.toHexStr(XorCipher.repeating(c4Plaintext, c4Key)));
	}
	
	public static void challenge6() throws Exception
	{
		// challege 6
		System.out.println("Testing Hamming Distance: " + HexUtils.HammingDistance(
				"this is a test".getBytes("UTF-8"), "wokka wokka!!!".getBytes("UTF-8")));
		
		byte[] ciphertext = FileUtils.readBase64("resources/set1_challenge6.txt");
		//byte[] plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean sed nisl in lacus feugiat commodo at vel purus. Nulla ornare dui lectus. In hac habitasse platea dictumst. Vestibulum tempus ante eu tincidunt dapibus. Maecenas magna eros, congue ac metus et, porttitor ultricies leo. Suspendisse mi massa, egestas et dui in, tristique semper felis. Cras in mi eros.".getBytes("ASCII");
		//byte[] testkey = "HelloWorldPassword".getBytes("ASCII");
		//byte[] ciphertext = XorCipher.repeating(plaintext, testkey);
		
		//System.out.println(HexUtils.toHexStr(ciphertext));
		
		ArrayList<KeyValuePair<Integer, Integer>> nrmlEditDistance = new ArrayList<KeyValuePair<Integer, Integer>>();
		
		// find the normalized distance for the keysizes
		for(int KEYSIZE=2; KEYSIZE<40; KEYSIZE++)
		{
			byte[] data1 = Arrays.copyOfRange(ciphertext, 0 * KEYSIZE, 1 * KEYSIZE);
			byte[] data2 = Arrays.copyOfRange(ciphertext, 1 * KEYSIZE, 2 * KEYSIZE);
			byte[] data3 = Arrays.copyOfRange(ciphertext, 2 * KEYSIZE, 3 * KEYSIZE);
			byte[] data4 = Arrays.copyOfRange(ciphertext, 3 * KEYSIZE, 4 * KEYSIZE);
			int totaldist = HexUtils.HammingDistance(data1, data2);
			totaldist += HexUtils.HammingDistance(data1, data3);
			totaldist += HexUtils.HammingDistance(data1, data4);
			totaldist += HexUtils.HammingDistance(data2, data3);
			totaldist += HexUtils.HammingDistance(data2, data4);
			totaldist += HexUtils.HammingDistance(data3, data4);
			
			nrmlEditDistance.add(new KeyValuePair<Integer, Integer>(KEYSIZE, totaldist / (KEYSIZE)));
		}
		
		// sort our list to get the top 4
		Collections.sort(nrmlEditDistance, new Comparator<KeyValuePair<Integer, Integer>>() {
			@Override
			public int compare(KeyValuePair<Integer, Integer> arg0, KeyValuePair<Integer, Integer> arg1) {
				return arg0.getValue().compareTo(arg1.getValue());
			}
		});
		
		// the best seem to be 5, 2, 3, and 11
		// my guess is 5
		System.out.println("Best key sizes are: " + nrmlEditDistance.get(0).getKey()  + "(" + nrmlEditDistance.get(0).getValue()
				+ "), " + nrmlEditDistance.get(1).getKey() + "(" + nrmlEditDistance.get(1).getValue() 
				+ "), " + nrmlEditDistance.get(2).getKey() + "(" + nrmlEditDistance.get(2).getValue() 
				+ "), " + nrmlEditDistance.get(3).getKey() + "(" + nrmlEditDistance.get(3).getValue() + ")");
		
		// you can change this to try the top keysizes
		for(int i=0; i<1; i++)
		{
			int keysize = nrmlEditDistance.get(i).getKey();
			System.out.println("trying keysize " + keysize);
			byte[] key = new byte[keysize];
			
			// split the data into keysize length blocks
			byte[][] data = new byte[ciphertext.length/keysize][keysize];
			int pos = 0;
			for(int j=0; j<ciphertext.length/keysize; j++)
			{
				for(int l=0; l<keysize; l++)
					data[j][l] = ciphertext[pos++];
			}
					
			byte[][] transpose = new byte[keysize][ciphertext.length/keysize];
			
			// transpose the data to let us access elements with the same xor key
			for(int r=0; r<data.length; r++)
			{
				for(int c=0; c<data[0].length; c++)
				{
					transpose[c][r] = data[r][c];
				}
			}
			
			for(int k=0; k<keysize; k++)
			{
				// here we should have a buffer with every byte using the same single byte xor key
				// now solve the single byte xor
				//System.out.print("possible values for key pos " + k + ": ");
				for(int j = 0; j < 255; j++)
				{
					byte[] decoded = XorCipher.single(transpose[k], (byte)j);
					double score = HexUtils.stringMetric(decoded);
					if(score > 0.85) // mess with this score to get values to come in and drop out.
									// anywhere from 80% to 95% works
					{
						//System.out.print((char)j + ", ");
						key[k] = (byte)j;
					}
				}
				//System.out.println();
			}
			System.out.println("Guessed Key: " + HexUtils.toNormalStr(key));
			System.out.println(HexUtils.toNormalStr(XorCipher.repeating(ciphertext, key)));
		}
	}
	
	public static void challenge7() throws Exception
	{
		byte[] keyBytes = "YELLOW SUBMARINE".getBytes("UTF-8");
		AESKey k = new AESKey(keyBytes);
		// byte[] cipherText = FileUtils.readBase64("resources/set1_challenge7_test.txt");
		byte[] plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec elit sapien, laoreet non sem eget, laoreet pellentesque lectus. Aliquam tincidunt purus nec nunc mollis, et lacinia leo lobortis. Nunc porta tincidunt libero, aliquet tempor tellus vestibulum ac. In euismod quis leo in feugiat. Vivamus rutrum, nisi eget dapibus molestie, odio magna consectetur dui, vel condimentum erat nulla a felis. Ut eu facilisis neque. Nunc a hendrerit metus. Morbi facilisis nibh ante. Vestibulum sem magna, semper ut est in, eleifend egestas lacus. Mauris sit amet arcu sollicitudin, malesuada augue nec, sagittis augue. Donec consectetur hendrerit purus a mattis. Ut euismod sapien sed fringilla porttitor. Nullam rutrum fringilla commodo. Aliquam eu luctus erat, et convallis sapien. Aliquam eleifend massa at ipsum molestie iaculis."
				.getBytes("UTF-8");
		AESCipher cipher = new AESCipher(k, AESCipher.CIPHER_MODE_ENCRYPT, AESCipher.BLOCK_MODE_ECB, AESCipher.PADDING_NONE);
		cipher.initData(plainText);
		cipher.run();
		System.out.println(HexUtils.toHexStr(cipher.getResult()));	
	}
	
	public static void challenge8()
	{
		String[] cipherTexts = FileUtils.readLines("resources/set1_challenge8.txt");
		int line = 1;
		for(String cText : cipherTexts)
		{
			byte[] cipher = HexUtils.toByteArray(cText);
			byte[][] data = new byte[cipher.length / 16][16];
			int pos = 0;
			for(int j=0; j<cipher.length/16; j++)
			{
				for(int l=0; l<16; l++)
					data[j][l] = cipher[pos++];
			}
			boolean breakout = false;
			for(int i=0; i<data.length; i++) {
				if(breakout) break;
				for(int j=0; j<data.length; j++) {
					if(i == j) continue;
					if(Arrays.equals(data[i], data[j])) {
						System.out.println("Line " + line + " Could be CBC");
						breakout = true;
						break;
					}		
				}
			}
			line++;
		}
	}

	public static void main(String[] args) throws Exception { // yay just throw exceptions at hotspot!
		/*
		challenge1();
		System.out.println("----------------------------------------");
		challenge2();		
		System.out.println("----------------------------------------");
		challenge3();		
		System.out.println("----------------------------------------");
		challenge4();
		System.out.println("----------------------------------------");
		challenge5();		
		System.out.println("----------------------------------------");
		challenge6();
		System.out.println("----------------------------------------");
		*/
		challenge7();
		//System.out.println("----------------------------------------");
		//challenge8();
	}

}
