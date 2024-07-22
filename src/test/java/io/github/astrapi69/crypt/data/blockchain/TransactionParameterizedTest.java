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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized test class for {@link Transaction}.
 */
public class TransactionParameterizedTest
{

	/**
	 * Provides test data for the parameterized test.
	 *
	 * @return a stream of arguments for the test
	 */
	static Stream<org.junit.jupiter.params.provider.Arguments> transactionProvider()
	{
		return Stream.of(
			org.junit.jupiter.params.provider.Arguments.of("text1", "sender1".getBytes(),
				"signature1".getBytes(), 1622547600000L),
			org.junit.jupiter.params.provider.Arguments.of("text2", "sender2".getBytes(),
				"signature2".getBytes(), 1622634000000L));
	}

	/**
	 * Parameterized test for {@link Transaction} using a CSV file source.
	 *
	 * @param text
	 *            the text of the transaction
	 * @param senderHash
	 *            the sender hash
	 * @param signature
	 *            the signature
	 * @param timestamp
	 *            the timestamp
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/transaction-data.csv", numLinesToSkip = 1)
	public void testTransactionFromCsv(String text,
		@ConvertWith(StringToByteArrayConverter.class) byte[] senderHash,
		@ConvertWith(StringToByteArrayConverter.class) byte[] signature, long timestamp)
	{
		Transaction transaction = new Transaction(text, senderHash, signature);
		transaction.setTimestamp(timestamp);

		assertEquals(text, transaction.getText());
		assertArrayEquals(senderHash, transaction.getSenderHash());
		assertArrayEquals(signature, transaction.getSignature());
		assertEquals(timestamp, transaction.getTimestamp());
	}

	/**
	 * Parameterized test for {@link Transaction} using a method source.
	 *
	 * @param text
	 *            the text of the transaction
	 * @param senderHash
	 *            the sender hash
	 * @param signature
	 *            the signature
	 * @param timestamp
	 *            the timestamp
	 */
	@ParameterizedTest
	@MethodSource("transactionProvider")
	public void testTransactionFromMethodSource(String text, byte[] senderHash, byte[] signature,
		long timestamp)
	{
		Transaction transaction = new Transaction(text, senderHash, signature);
		transaction.setTimestamp(timestamp);

		assertEquals(text, transaction.getText());
		assertArrayEquals(senderHash, transaction.getSenderHash());
		assertArrayEquals(signature, transaction.getSignature());
		assertEquals(timestamp, transaction.getTimestamp());
	}
}
