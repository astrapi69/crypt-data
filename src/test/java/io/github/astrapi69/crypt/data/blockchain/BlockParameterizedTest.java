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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * Parameterized test class for {@link Block} using a CSV file
 */
public class BlockParameterizedTest
{

	/**
	 * Parameterized test method for {@link Block} using data from a CSV file
	 *
	 * @param hash
	 *            the hash of the block
	 * @param merkleRoot
	 *            the Merkle root of the block's transactions
	 * @param previousBlockHash
	 *            the hash of the previous block
	 * @param timestamp
	 *            the timestamp when the block was created
	 * @param tries
	 *            the number of attempts to find a valid hash
	 * @param data
	 *            the data field for additional information in the block
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/block_test_data.csv", numLinesToSkip = 1)
	public void testBlockWithCsvData(@ConvertWith(StringToByteArrayConverter.class) byte[] hash,
		@ConvertWith(StringToByteArrayConverter.class) byte[] merkleRoot,
		@ConvertWith(StringToByteArrayConverter.class) byte[] previousBlockHash, long timestamp,
		long tries, String data)
	{
		Block block = new Block();
		block.setHash(hash);
		block.setMerkleRoot(merkleRoot);
		block.setPreviousBlockHash(previousBlockHash);
		block.setTimestamp(timestamp);
		block.setTries(tries);
		block.setData(data);

		assertNotNull(block.getHash());
		assertNotNull(block.getMerkleRoot());
		assertNotNull(block.getPreviousBlockHash());
		assertNotNull(block.getTimestamp());
		assertNotNull(block.getTries());
		assertNotNull(block.getData());

		assertEquals(data, block.getData());
		assertEquals(timestamp, block.getTimestamp());
		assertEquals(tries, block.getTries());
		assertTrue(Arrays.equals(hash, block.getHash()));
		assertTrue(Arrays.equals(merkleRoot, block.getMerkleRoot()));
		assertTrue(Arrays.equals(previousBlockHash, block.getPreviousBlockHash()));
	}
}
