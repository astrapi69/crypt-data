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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.factory.ShamirSecretSharingFactory.Share;

/**
 * Parameterized tests for {@link ShamirSecretSharingFactory}: round trips over several
 * threshold/share combinations, the argument guards and the immutability of {@link Share}
 */
class ShamirSecretSharingFactoryParameterizedTest
{

	private static final SecureRandom RANDOM = new SecureRandom();

	/**
	 * One split configuration
	 *
	 * @param secretLength
	 *            the length of the secret in bytes
	 * @param threshold
	 *            the number of shares needed to reconstruct the secret
	 * @param totalShares
	 *            the number of generated shares
	 */
	record SplitCase(int secretLength, int threshold, int totalShares) {
	}

	/**
	 * One invalid invocation
	 *
	 * @param description
	 *            what is invalid
	 * @param call
	 *            the invocation
	 * @param expectedException
	 *            the expected exception type
	 * @param expectedMessagePart
	 *            the text the exception message must contain or null if no message is checked
	 */
	record InvalidCallCase(String description, Executable call,
		Class<? extends Throwable> expectedException, String expectedMessagePart) {
	}

	private static byte[] newSecret(final int length)
	{
		byte[] secret = new byte[length];
		RANDOM.nextBytes(secret);
		return secret;
	}

	static Stream<SplitCase> splitCases()
	{
		return Stream.of(new SplitCase(16, 2, 3), new SplitCase(32, 3, 5), new SplitCase(32, 5, 5),
			new SplitCase(8, 2, 8), new SplitCase(64, 4, 7));
	}

	/**
	 * Test method for {@link ShamirSecretSharingFactory#split(byte[], int, int, SecureRandom)} and
	 * {@link ShamirSecretSharingFactory#combine(List)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("splitCases")
	void splitAndCombineRoundTrip(final SplitCase testCase)
	{
		byte[] secret = newSecret(testCase.secretLength());

		List<Share> shares = ShamirSecretSharingFactory.split(secret, testCase.threshold(),
			testCase.totalShares(), RANDOM);

		assertEquals(testCase.totalShares(), shares.size());
		for (int i = 0; i < shares.size(); i++)
		{
			Share share = shares.get(i);
			assertEquals(i + 1, share.getIndex());
			assertEquals(testCase.secretLength(), share.getValue().length);
			// a single share must never reveal the secret
			assertFalse(Arrays.equals(secret, share.getValue()));
		}
		// any subset of threshold shares reconstructs the secret
		assertArrayEquals(secret,
			ShamirSecretSharingFactory.combine(shares.subList(0, testCase.threshold())));
		assertArrayEquals(secret, ShamirSecretSharingFactory.combine(
			shares.subList(testCase.totalShares() - testCase.threshold(), testCase.totalShares())));
		List<Share> reversed = new java.util.ArrayList<>(shares);
		Collections.reverse(reversed);
		assertArrayEquals(secret,
			ShamirSecretSharingFactory.combine(reversed.subList(0, testCase.threshold())));
		assertArrayEquals(secret, ShamirSecretSharingFactory.combine(shares));
	}

	static Stream<InvalidCallCase> invalidCallCases()
	{
		byte[] secret = newSecret(4);
		return Stream.of(
			new InvalidCallCase("empty secret",
				() -> ShamirSecretSharingFactory.split(new byte[0], 2, 3, RANDOM),
				IllegalArgumentException.class, "secret must not be empty"),
			new InvalidCallCase("null secret",
				() -> ShamirSecretSharingFactory.split(null, 2, 3, RANDOM),
				NullPointerException.class, null),
			new InvalidCallCase("null random",
				() -> ShamirSecretSharingFactory.split(secret, 2, 3, null),
				NullPointerException.class, null),
			new InvalidCallCase("more shares than secret bytes",
				() -> ShamirSecretSharingFactory.split(secret, 2, 5, RANDOM),
				IllegalArgumentException.class, "must not exceed the secret length"),
			new InvalidCallCase("empty shares",
				() -> ShamirSecretSharingFactory.combine(Collections.emptyList()),
				IllegalArgumentException.class, "shares must not be empty"),
			new InvalidCallCase("null shares", () -> ShamirSecretSharingFactory.combine(null),
				NullPointerException.class, null),
			new InvalidCallCase("null share value", () -> new Share(1, null),
				NullPointerException.class, null),
			new InvalidCallCase("threshold above total shares",
				() -> ShamirSecretSharingFactory.split(secret, 3, 2, RANDOM),
				IllegalArgumentException.class, null));
	}

	/**
	 * Test method for the argument guards of {@link ShamirSecretSharingFactory}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("invalidCallCases")
	void rejectsInvalidArguments(final InvalidCallCase testCase)
	{
		Throwable actual = assertThrows(testCase.expectedException(), testCase.call(),
			testCase.description());
		if (testCase.expectedMessagePart() != null)
		{
			assertTrue(actual.getMessage().contains(testCase.expectedMessagePart()),
				actual.getMessage());
		}
	}

	/**
	 * Test method for the defensive copies of {@link Share}
	 */
	@Test
	void shareIsImmutable()
	{
		byte[] value = { 1, 2, 3 };
		Share share = new Share(7, value);

		value[0] = 9;
		assertEquals(1, share.getValue()[0]);
		share.getValue()[1] = 9;
		assertEquals(2, share.getValue()[1]);
		assertEquals(7, share.getIndex());
		assertArrayEquals(new byte[] { 1, 2, 3 }, share.getValue());
	}
}
