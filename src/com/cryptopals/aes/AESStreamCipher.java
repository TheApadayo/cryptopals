package com.cryptopals.aes;

public class AESStreamCipher extends AESCipher {
	
	byte[] _Nonce;
	byte[] curBlock;
	
	int streamCtr, streamPos;

	public AESStreamCipher(AESKey k) {
		super(k);
		streamCtr = 0;
		streamPos = 0;
		curBlock = new byte[AESCipher.BLOCKSIZE];
	}
	
	public void setNonce(byte[] n)
	{
		if(n.length != 8)
			throw new EncryptionException("Nonce must be 8 bytes long!");
		_Nonce = n;
	}
	
	private void generateKeyBytes()
	{
		curBlock[0] = _Nonce[0];
		curBlock[1] = _Nonce[1];
		curBlock[2] = _Nonce[2];
		curBlock[3] = _Nonce[3];
		curBlock[4] = _Nonce[4];
		curBlock[5] = _Nonce[5];
		curBlock[6] = _Nonce[6];
		curBlock[7] = _Nonce[7];
		curBlock[8] = (byte)((streamCtr >> 0) & 0xFF);
		curBlock[9] = (byte)((streamCtr >> 8) & 0xFF);
		curBlock[10] = (byte)((streamCtr >> 16) & 0xFF);
		curBlock[11] = (byte)((streamCtr >> 24) & 0xFF);
		curBlock[12] = (byte)((streamCtr >> 32) & 0xFF);
		curBlock[13] = (byte)((streamCtr >> 40) & 0xFF);
		curBlock[14] = (byte)((streamCtr >> 48) & 0xFF);
		curBlock[15] = (byte)((streamCtr >> 56) & 0xFF);
		streamCtr++;
		encryptBlock(curBlock);
	}
	
	public void process(byte[] d)
	{
		for(int i=0; i<d.length; i+=AESCipher.BLOCKSIZE)
		{
			for(int j=0; j<AESCipher.BLOCKSIZE; j++)
			{
				d[i + j] ^= curBlock[streamPos % AESCipher.BLOCKSIZE];
				streamPos++;
				if(streamPos % AESCipher.BLOCKSIZE == 0)
					generateKeyBytes();
			}
		}
	}
	
	public void reset()
	{
		streamCtr = 0;
		streamPos = 0;
	}

}
