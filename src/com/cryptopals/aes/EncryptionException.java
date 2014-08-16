package com.cryptopals.aes;

public class EncryptionException extends RuntimeException {
	private static final long serialVersionUID = 1L;
	
	public EncryptionException(String message)
	{
		super(message);
	}

}
