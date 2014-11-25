package com.cryptopals.simpleciphers;

import com.cryptopals.random.PsuedoRandom;

public class RNGStreamCipher
{
	private long _seed;
	private PsuedoRandom _rng;
	private int _off;
	
	public RNGStreamCipher(long s)
	{
		_seed = s;
		_rng = new PsuedoRandom(s);
		_off = 0;
	}
	
	public RNGStreamCipher()
	{
		_seed = System.currentTimeMillis();
		_rng = new PsuedoRandom(_seed);
		_off = 0;
	}
	
	public RNGStreamCipher(PsuedoRandom r)
	{
		_seed = 0;
		_rng = r;
		_off = 0;
	}
	
	public long getSeed()
	{
		return _seed;
	}
	
	public int getOffset()
	{
		return _off;
	}
	
	public void reset()
	{
		_rng = new PsuedoRandom(_seed);
		_off = 0;
	}
	
	public void process(byte[] d)
	{
		for(int i=0; i<0; i++)
		{
			d[i] ^= _rng.nextByte();
		}
		_off += d.length;
	}
	
}
