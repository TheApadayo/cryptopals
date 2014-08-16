package com.cryptopals.utils;

import java.io.*;
import java.util.*;




public class FileUtils {

	public static byte[] readBase64(String file) {
		String filetext = "";
		String line;
		try {	
			BufferedReader input = new BufferedReader(new FileReader(new File(
					file)));
			while ((line = input.readLine()) != null) {
				filetext += line;
			}
			input.close();
		} catch (IOException e) {
		}
		return Base64Converter.Base64toBytes(filetext);
	}
	
	public static String[] readLines(String file) {
		ArrayList<String> lines = new ArrayList<String>();
		String line;
		try {	
			BufferedReader input = new BufferedReader(new FileReader(new File(
					file)));
			while ((line = input.readLine()) != null) {
				lines.add(line);
			}
			input.close();
		} catch (IOException e) {
		}
		String[] ret = new String[lines.size()];
		lines.toArray(ret);
		return ret;
	}
	
	public static String readFull(String file) {
		String ret = "";
		String line;
		try {	
			BufferedReader input = new BufferedReader(new FileReader(new File(
					file)));
			while ((line = input.readLine()) != null) {
				ret += line;
			}
			input.close();
		} catch (IOException e) {
		}
		return ret;
	}

}
