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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.blockchain.ITransaction;

/**
 * Pins the {@code hashCode()} algorithm of {@link Address}, {@link Block} and {@link Transaction}
 * to the Lombok-style formula they implement (prime 59, {@code 43} for a null reference,
 * {@code (int)(l >>> 32 ^ l)} for a long). The values take part in the blockchain identity of the
 * objects, so a silent change of the formula must be caught
 */
class BlockchainHashCodeContractParameterizedTest
{

	private static final int PRIME = 59;
	private static final int NULL_HASH = 43;

	/** A timestamp above 2^32 so that the upper 32 bits matter in the long folding */
	private static final long HIGH_BITS_TIMESTAMP = 0x1234_5678_9ABC_DEF0L;

	/**
	 * One object together with its independently computed reference hash
	 *
	 * @param description
	 *            what the case covers
	 * @param object
	 *            the object under test
	 * @param expectedHashCode
	 *            the reference hash computed in the test
	 */
	record HashCase(String description, Object object, int expectedHashCode) {
	}

	private static int foldLong(final long value)
	{
		return (int)(value >>> 32 ^ value);
	}

	private static int referenceHash(final Address address)
	{
		int result = 1;
		result = result * PRIME + Arrays.hashCode(address.getHash());
		result = result * PRIME
			+ (address.getName() == null ? NULL_HASH : address.getName().hashCode());
		result = result * PRIME + Arrays.hashCode(address.getPublicKey());
		return result;
	}

	private static int referenceHash(final Block block)
	{
		int result = 1;
		result = result * PRIME + Arrays.hashCode(block.getHash());
		result = result * PRIME + Arrays.hashCode(block.getMerkleRoot());
		result = result * PRIME + Arrays.hashCode(block.getPreviousBlockHash());
		result = result * PRIME + foldLong(block.getTimestamp());
		result = result * PRIME
			+ (block.getTransactions() == null ? NULL_HASH : block.getTransactions().hashCode());
		result = result * PRIME + foldLong(block.getTries());
		return result;
	}

	private static int referenceHash(final Transaction transaction)
	{
		int result = 1;
		result = result * PRIME + Arrays.hashCode(transaction.getHash());
		result = result * PRIME + Arrays.hashCode(transaction.getSenderHash());
		result = result * PRIME + Arrays.hashCode(transaction.getSignature());
		result = result * PRIME
			+ (transaction.getText() == null ? NULL_HASH : transaction.getText().hashCode());
		result = result * PRIME + foldLong(transaction.getTimestamp());
		return result;
	}

	private static byte[] bytes(final String value)
	{
		return value.getBytes(StandardCharsets.UTF_8);
	}

	static Stream<HashCase> hashCases()
	{
		Address emptyAddress = new Address();
		Address address = new Address("alice", bytes("public-key"));

		Transaction emptyTransaction = new Transaction();
		Transaction transaction = new Transaction("pay 1 coin", bytes("sender"),
			bytes("signature"));
		transaction.setTimestamp(HIGH_BITS_TIMESTAMP);

		Block emptyBlock = new Block();
		Block block = new Block(bytes("previous"), List.<ITransaction> of(transaction), 7L);
		block.setTimestamp(HIGH_BITS_TIMESTAMP);
		block.setTries(HIGH_BITS_TIMESTAMP + 1);

		return Stream.of(new HashCase("empty address", emptyAddress, referenceHash(emptyAddress)),
			new HashCase("address", address, referenceHash(address)),
			new HashCase("empty transaction", emptyTransaction, referenceHash(emptyTransaction)),
			new HashCase("transaction with high-bit timestamp", transaction,
				referenceHash(transaction)),
			new HashCase("empty block", emptyBlock, referenceHash(emptyBlock)),
			new HashCase("block with high-bit timestamp and tries", block, referenceHash(block)));
	}

	/**
	 * Test method for {@link Address#hashCode()}, {@link Block#hashCode()} and
	 * {@link Transaction#hashCode()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("hashCases")
	void hashCodeFollowsReferenceFormula(final HashCase testCase)
	{
		assertEquals(testCase.expectedHashCode(), testCase.object().hashCode(),
			testCase.description());
		assertNotEquals(0, testCase.object().hashCode(), testCase.description());
	}

	/**
	 * Test method for {@link Block#hashCode()} and {@link Transaction#hashCode()}: the upper 32
	 * bits of the long fields must influence the hash
	 */
	@Test
	void longFieldsContributeTheirUpperBits()
	{
		Transaction low = new Transaction();
		Transaction high = new Transaction();
		low.setTimestamp(1L);
		high.setTimestamp(1L | 1L << 40);
		assertNotEquals(low.hashCode(), high.hashCode());

		Block lowTries = new Block();
		Block highTries = new Block();
		lowTries.setTries(1L);
		highTries.setTries(1L | 1L << 40);
		assertNotEquals(lowTries.hashCode(), highTries.hashCode());
	}

	/**
	 * Test method for {@link Address#canEqual(Object)}
	 */
	@Test
	void canEqualAcceptsOnlyAddresses()
	{
		Address address = new Address("bob", bytes("key"));
		assertTrue(address.canEqual(new Address()));
		assertTrue(address.canEqual(address));
		assertFalse(address.canEqual("bob"));
		assertFalse(address.canEqual(null));
	}
}
