package com.cryptopals.aes;

public class AESBlock {

	byte[] block;

	public AESBlock(byte[] data) {
		if (data.length != 16)
			throw new EncryptionException("Invalid Block Size");
		block = data;
	}

	protected byte getByte(int a, int b) {
		if (a > 4 || b >= 4)
			throw new EncryptionException(
					"Trying to access non-existant part of Block");
		return block[4 * a + b];
	}

	protected void setByte(int a, int b, byte data) {
		if (a > 4 || b >= 4)
			throw new EncryptionException(
					"Trying to access non-existant part of Block");
		block[4 * a + b] = data;
	}
	
	protected byte[] getRow(int r)
	{
		byte[] ret = new byte[4];
		ret[0] = getByte(0, r);
		ret[1] = getByte(1, r);
		ret[2] = getByte(2, r);
		ret[3] = getByte(3, r);
		return ret;
	}
	
	protected void setRow(int r, byte[] data)
	{
		setByte(0, r, data[0]);
		setByte(1, r, data[1]);
		setByte(2, r, data[2]);
		setByte(3, r, data[3]);
	}

	protected byte[] getData() {
		return block;
	}

	protected void setData(byte[] data) {
		block = data;
	}

}
