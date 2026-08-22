/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.threshold.ShamirSecretSplitter;
import org.bouncycastle.crypto.threshold.ShamirSplitSecret;
import org.bouncycastle.crypto.threshold.ShamirSplitSecretShare;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.factory.ShamirSecretSharingFactory.Share;

/**
 * The unit test class for the class {@link ShamirSecretSharingFactory}
 */
public class ShamirSecretSharingFactoryTest
{

	private static final SecureRandom RANDOM = new SecureRandom();

	private byte[] newSecret(final int length)
	{
		final byte[] secret = new byte[length];
		RANDOM.nextBytes(secret);
		return secret;
	}

	/**
	 * Test method for {@link ShamirSecretSharingFactory#split(byte[], int, int, SecureRandom)} and
	 * {@link ShamirSecretSharingFactory#combine(List)}
	 */
	@Test
	public void testSplitAndCombineWithExactThreshold() throws Exception
	{
		final byte[] secret = newSecret(32);

		final List<Share> shares = ShamirSecretSharingFactory.split(secret, 3, 5, RANDOM);
		assertEquals(5, shares.size());

		final List<Share> subset = shares.subList(0, 3);
		final byte[] recovered = ShamirSecretSharingFactory.combine(subset);

		assertArrayEquals(secret, recovered);
	}

	/**
	 * Test method for {@link ShamirSecretSharingFactory#combine(List)} with a different subset of
	 * shares than the one used in {@link #testSplitAndCombineWithExactThreshold()}
	 */
	@Test
	public void testCombineWithDifferentSubsetOfShares() throws Exception
	{
		final byte[] secret = newSecret(32);

		final List<Share> shares = ShamirSecretSharingFactory.split(secret, 3, 5, RANDOM);

		final List<Share> subset = new ArrayList<>();
		subset.add(shares.get(1));
		subset.add(shares.get(3));
		subset.add(shares.get(4));

		final byte[] recovered = ShamirSecretSharingFactory.combine(subset);

		assertArrayEquals(secret, recovered);
	}

	/**
	 * Test method for {@link ShamirSecretSharingFactory#combine(List)} with more shares than the
	 * threshold
	 */
	@Test
	public void testCombineWithMoreSharesThanThreshold() throws Exception
	{
		final byte[] secret = newSecret(32);

		final List<Share> shares = ShamirSecretSharingFactory.split(secret, 3, 5, RANDOM);

		final byte[] recovered = ShamirSecretSharingFactory.combine(shares);

		assertArrayEquals(secret, recovered);
	}

	/**
	 * Test method for {@link ShamirSecretSharingFactory#combine(List)} with fewer shares than the
	 * threshold: reconstruction is not detected as invalid (Shamir's scheme has no built-in
	 * integrity check) but silently yields a wrong result.
	 */
	@Test
	public void testCombineWithFewerSharesThanThresholdYieldsWrongSecret() throws Exception
	{
		final byte[] secret = newSecret(32);

		final List<Share> shares = ShamirSecretSharingFactory.split(secret, 3, 5, RANDOM);
		final List<Share> tooFew = shares.subList(0, 2);

		final byte[] recovered = ShamirSecretSharingFactory.combine(tooFew);

		assertFalse(Arrays.equals(secret, recovered));
	}

	/**
	 * Test method for {@link ShamirSecretSharingFactory#split(byte[], int, int, SecureRandom)} with
	 * a totalShares count exceeding the secret length
	 */
	@Test
	public void testSplitRejectsTotalSharesExceedingSecretLength()
	{
		final byte[] secret = newSecret(3);

		assertThrows(IllegalArgumentException.class,
			() -> ShamirSecretSharingFactory.split(secret, 3, 5, RANDOM));
	}

	/**
	 * Test method for {@link ShamirSecretSharingFactory#split(byte[], int, int, SecureRandom)} with
	 * a small, realistic AES-128 key size
	 */
	@Test
	public void testSplitAndCombineWithAes128KeySize() throws Exception
	{
		final byte[] secret = newSecret(16);

		final List<Share> shares = ShamirSecretSharingFactory.split(secret, 2, 3, RANDOM);
		final byte[] recovered = ShamirSecretSharingFactory.combine(shares.subList(0, 2));

		assertArrayEquals(secret, recovered);
	}

	/**
	 * Test method for the {@link IOException} path of
	 * {@link ShamirSecretSharingFactory#encode(ShamirSplitSecretShare)}
	 * <p>
	 * Bouncy Castle's own {@link ShamirSplitSecretShare#getEncoded()} only clones an array and
	 * never fails, but {@code SecretShare#getEncoded()} declares {@link IOException} and the class
	 * is neither final nor has final methods, so an implementation that does throw is legal. The
	 * factory must translate such a failure into an {@link IllegalStateException} that keeps the
	 * original cause
	 */
	@Test
	public void testEncodeWrapsIoExceptionInIllegalStateException()
	{
		final IOException failure = new IOException("boom");
		final ShamirSplitSecretShare throwingShare = new ShamirSplitSecretShare(new byte[] { 1 }, 1)
		{
			@Override
			public byte[] getEncoded() throws IOException
			{
				throw failure;
			}
		};

		final IllegalStateException exception = assertThrows(IllegalStateException.class,
			() -> ShamirSecretSharingFactory.encode(throwingShare));

		assertEquals("Failed to encode a Shamir secret share", exception.getMessage());
		assertSame(failure, exception.getCause());
	}

	/**
	 * Test method for the {@link IOException} path of
	 * {@link ShamirSecretSharingFactory#decode(ShamirSplitSecret)}
	 * <p>
	 * Same reasoning as for {@link #testEncodeWrapsIoExceptionInIllegalStateException()}:
	 * {@code SplitSecret#getSecret()} declares {@link IOException} and
	 * {@link ShamirSplitSecret#getSecret()} is overridable
	 */
	@Test
	public void testDecodeWrapsIoExceptionInIllegalStateException()
	{
		final IOException failure = new IOException("bang");
		final ShamirSplitSecret throwingSecret = new ShamirSplitSecret(
			ShamirSecretSplitter.Algorithm.AES, ShamirSecretSplitter.Mode.Table,
			new ShamirSplitSecretShare[] { new ShamirSplitSecretShare(new byte[] { 1 }, 1) })
		{
			@Override
			public byte[] getSecret() throws IOException
			{
				throw failure;
			}
		};

		final IllegalStateException exception = assertThrows(IllegalStateException.class,
			() -> ShamirSecretSharingFactory.decode(throwingSecret));

		assertEquals("Failed to reconstruct the secret from its shares", exception.getMessage());
		assertSame(failure, exception.getCause());
	}

}
