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

import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.blockchain.ITransaction;

/**
 * Parameterized tests for the equals/hashCode contract of {@link Block}, including the null-field
 * branches that the constructor with arguments can never produce
 */
class BlockEqualsParameterizedTest
{

	private static final byte[] HASH = { 9, 8, 7 };
	private static final byte[] MERKLE_ROOT = { 1, 2, 3 };
	private static final byte[] PREVIOUS_BLOCK_HASH = { 4, 5, 6 };
	private static final long TIMESTAMP = 1_000L;
	private static final long TRIES = 42L;

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
	record EqualsCase(String description, Block first, Object second, boolean expectedEqual) {
	}

	private static List<ITransaction> newTransactions(final String text)
	{
		Transaction transaction = new Transaction();
		transaction.setText(text);
		return List.of(transaction);
	}

	private static Block newBlock(final List<ITransaction> transactions, final byte[] hash,
		final byte[] merkleRoot, final byte[] previousBlockHash, final long timestamp,
		final long tries)
	{
		Block block = new Block();
		block.setTransactions(transactions);
		block.setHash(hash);
		block.setMerkleRoot(merkleRoot);
		block.setPreviousBlockHash(previousBlockHash);
		block.setTimestamp(timestamp);
		block.setTries(tries);
		return block;
	}

	private static Block newBlock(final List<ITransaction> transactions)
	{
		return newBlock(transactions, HASH, MERKLE_ROOT, PREVIOUS_BLOCK_HASH, TIMESTAMP, TRIES);
	}

	static Stream<EqualsCase> equalsCases()
	{
		Block same = newBlock(newTransactions("foo"));
		return Stream.of(new EqualsCase("same instance", same, same, true),
			new EqualsCase("null", newBlock(newTransactions("foo")), null, false),
			new EqualsCase("other type", newBlock(newTransactions("foo")), "foo", false),
			new EqualsCase("identical fields", newBlock(newTransactions("foo")),
				newBlock(newTransactions("foo"), HASH.clone(), MERKLE_ROOT.clone(),
					PREVIOUS_BLOCK_HASH.clone(), TIMESTAMP, TRIES),
				true),
			new EqualsCase("all fields null", new Block(), new Block(), true),
			new EqualsCase("first transactions null", newBlock(null),
				newBlock(newTransactions("foo")), false),
			new EqualsCase("second transactions null", newBlock(newTransactions("foo")),
				newBlock(null), false),
			new EqualsCase("both transactions null", newBlock(null), newBlock(null), true),
			new EqualsCase("transactions differ", newBlock(newTransactions("foo")),
				newBlock(newTransactions("bar")), false),
			new EqualsCase("timestamps differ", newBlock(newTransactions("foo")),
				newBlock(newTransactions("foo"), HASH, MERKLE_ROOT, PREVIOUS_BLOCK_HASH,
					TIMESTAMP + 1, TRIES),
				false),
			new EqualsCase("tries differ", newBlock(newTransactions("foo")),
				newBlock(newTransactions("foo"), HASH, MERKLE_ROOT, PREVIOUS_BLOCK_HASH, TIMESTAMP,
					TRIES + 1),
				false),
			new EqualsCase("hashes differ", newBlock(newTransactions("foo")),
				newBlock(newTransactions("foo"), new byte[] { 0 }, MERKLE_ROOT, PREVIOUS_BLOCK_HASH,
					TIMESTAMP, TRIES),
				false),
			new EqualsCase("merkle roots differ", newBlock(newTransactions("foo")),
				newBlock(newTransactions("foo"), HASH, new byte[] { 0 }, PREVIOUS_BLOCK_HASH,
					TIMESTAMP, TRIES),
				false),
			new EqualsCase("previous block hashes differ", newBlock(newTransactions("foo")),
				newBlock(newTransactions("foo"), HASH, MERKLE_ROOT, new byte[] { 0 }, TIMESTAMP,
					TRIES),
				false));
	}

	/**
	 * Test method for {@link Block#equals(Object)} and {@link Block#hashCode()}
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
		if (testCase.second()instanceof Block other)
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
