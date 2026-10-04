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
package io.github.astrapi69.crypt.data.blockchain;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for the equals/hashCode contract of {@link Transaction}, including the
 * null-field branches that the constructor with arguments can never produce
 */
class TransactionEqualsParameterizedTest
{

	private static final byte[] HASH = { 9, 8, 7 };
	private static final byte[] SENDER_HASH = { 1, 2, 3 };
	private static final byte[] SIGNATURE = { 4, 5, 6 };
	private static final long TIMESTAMP = 1_000L;

	/**
	 * One equality comparison
	 *
	 * @param description
	 *            what is compared
	 * @param first
	 *            the object whose equals method is invoked
	 * @param second
	 *            the argument of the equals method
	 * @param expectedEqual
	 *            the expected result
	 */
	record EqualsCase(String description, Transaction first, Object second, boolean expectedEqual) {
	}

	private static Transaction newTransaction(final String text, final byte[] senderHash,
		final byte[] signature, final byte[] hash, final long timestamp)
	{
		Transaction transaction = new Transaction();
		transaction.setText(text);
		transaction.setSenderHash(senderHash);
		transaction.setSignature(signature);
		transaction.setHash(hash);
		transaction.setTimestamp(timestamp);
		return transaction;
	}

	private static Transaction newTransaction(final String text)
	{
		return newTransaction(text, SENDER_HASH, SIGNATURE, HASH, TIMESTAMP);
	}

	static Stream<EqualsCase> equalsCases()
	{
		Transaction same = newTransaction("foo");
		return Stream.of(new EqualsCase("same instance", same, same, true),
			new EqualsCase("null", newTransaction("foo"), null, false),
			new EqualsCase("other type", newTransaction("foo"), "foo", false),
			new EqualsCase("identical fields", newTransaction("foo"),
				newTransaction("foo", SENDER_HASH.clone(), SIGNATURE.clone(), HASH.clone(),
					TIMESTAMP),
				true),
			new EqualsCase("all fields null", new Transaction(), new Transaction(), true),
			new EqualsCase("first text null", newTransaction(null), newTransaction("foo"), false),
			new EqualsCase("second text null", newTransaction("foo"), newTransaction(null), false),
			new EqualsCase("both texts null", newTransaction(null), newTransaction(null), true),
			new EqualsCase("texts differ", newTransaction("foo"), newTransaction("bar"), false),
			new EqualsCase("timestamps differ", newTransaction("foo"),
				newTransaction("foo", SENDER_HASH, SIGNATURE, HASH, TIMESTAMP + 1), false),
			new EqualsCase("hashes differ", newTransaction("foo"),
				newTransaction("foo", SENDER_HASH, SIGNATURE, new byte[] { 0 }, TIMESTAMP), false),
			new EqualsCase("sender hashes differ", newTransaction("foo"),
				newTransaction("foo", new byte[] { 0 }, SIGNATURE, HASH, TIMESTAMP), false),
			new EqualsCase("signatures differ", newTransaction("foo"),
				newTransaction("foo", SENDER_HASH, new byte[] { 0 }, HASH, TIMESTAMP), false),
			new EqualsCase("first signature null", newTransaction("foo"),
				newTransaction("foo", SENDER_HASH, null, HASH, TIMESTAMP), false));
	}

	/**
	 * Test method for {@link Transaction#equals(Object)} and {@link Transaction#hashCode()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("equalsCases")
	void equalsContract(final EqualsCase testCase)
	{
		assertEquals(testCase.expectedEqual(), testCase.first().equals(testCase.second()),
			testCase.description());
		if (testCase.second()instanceof Transaction other)
		{
			assertEquals(testCase.expectedEqual(), other.equals(testCase.first()),
				"symmetry: " + testCase.description());
			if (testCase.expectedEqual())
			{
				assertEquals(testCase.first().hashCode(), other.hashCode(), testCase.description());
			}
		}
	}
}
