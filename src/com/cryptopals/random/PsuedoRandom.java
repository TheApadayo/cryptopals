package com.cryptopals.random;


public final class PsuedoRandom {

    private final static int UPPER_MASK = 0x80000000;
    private final static int LOWER_MASK = 0x7fffffff;

    private final static int N = 624;
    private final static int M = 397;
    private final static int U = 11;
    private final static int L = 18;
    private final static int S = 7;
    private final static int T = 15;
    private final static int A[] = {0x0, 0x9908b0df};
    private final static int B = 0x9d2c5680;
    private final static int C = 0xefc60000;

    private transient int[] state;
    private transient int index;

    public PsuedoRandom() {
            setSeed(System.currentTimeMillis());
    }

    public PsuedoRandom(byte[] buffer) {
            setSeed(buffer);
    }

    public PsuedoRandom(long seed) {
            setSeed(seed);
    }

    public final synchronized void setSeed(long seed) {
            setSeed(new int[] {(int) seed, (int) (seed >>> 32)});
    }

    public final void setSeed(byte[] buffer) {
            setSeed(packBytes(buffer));
    }

    private final void setSeed(int seed) {
            if (state == null) {
                    state = new int[N];
            }
            state[0] = seed;
            for (index = 1; index < N; index++) {
                    state[index] = (1812433253 * (state[index - 1] ^ (state[index - 1] >>> 30)) + index);
            }
    }

    public final synchronized void setSeed(int[] buffer) {
            int i = 1;
            int j = 0;
            int k = (N > buffer.length ? N : buffer.length);

            setSeed(19650218);
            for (; k > 0; k--) {
                    state[i] = (state[i] ^ ((state[i] - 1 ^ (state[i - 1] >>> 30)) * 1664525)) + buffer[j]
                            + j;
                    i++;
                    j++;
                    if (i >= N) {
                            state[0] = state[N - 1];
                            i = 1;
                    }
                    if (j >= buffer.length) {
                            j = 0;
                    }
            }
            for (k = N - 1; k > 0; k--) {
                    state[i] = (state[i] ^ ((state[i] - 1 ^ (state[i - 1] >>> 30)) * 1566083941)) - i;
                    i++;
                    if (i >= N) {
                            state[0] = state[N - 1];
                            i = 1;
                    }
            }
            state[0] = UPPER_MASK;
    }

    public final synchronized int next(int bits) {
            int y, i;
            if (index >= N) {
                    for (i = 0; i < N - M; i++) {
                            y = (state[i] & UPPER_MASK) | (state[i + 1] & LOWER_MASK);
                            state[i] = state[i + M] ^ (y >>> 1) ^ A[y & 0x1];
                    }
                    for (; i < N - 1; i++) {
                            y = (state[i] & UPPER_MASK) | (state[i + 1] & LOWER_MASK);
                            state[i] = state[i + (M - N)] ^ (y >>> 1) ^ A[y & 0x1];
                    }
                    y = (state[N - 1] & UPPER_MASK) | (state[0] & LOWER_MASK);
                    state[N - 1] = state[M - 1] ^ (y >>> 1) ^ A[y & 0x1];

                    index = 0;
            }
            y = state[index++];
            y ^= (y >>> U);
            y ^= (y << S) & B;
            y ^= (y << T) & C;
            y ^= (y >>> L);
            
            return (y >>> (32 - bits));
    }
    
    public final synchronized int nextInt()
    {
    	return next(32);
    }

    public static int[] packBytes(byte[] buffer) {
            int size = ((buffer.length + 3) >>> 2);
            int[] result = new int[size];

            int value;
            for (int i = 0; i < size; i++) {
                    int j = (i + 1) << 2;
                    if (j > buffer.length) {
                            j = buffer.length;
                    }

                    value = buffer[--j] & 0xff;
                    while ((j & 0x3) != 0) {
                            value = (value << 8) | buffer[--j] & 0xff;
                    }
                    result[i] = value;
            }
            return result;
    }
    
    public static PsuedoRandom cloneFromState(int[] s)
    {
    	if(s.length != 624) throw new IllegalArgumentException("Can't clone state if it isnt 624 bytes!");
    	PsuedoRandom r = new PsuedoRandom();
    	for(int i=0; i<624; i++)
    		r.state[i] = s[i];
    	r.index = N;
    	return r;
    }
}