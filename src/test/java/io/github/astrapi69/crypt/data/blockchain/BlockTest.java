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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.api.blockchain.ITransaction;
import io.github.astrapi69.crypt.data.hash.HashExtensions;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.evaluate.object.evaluator.EqualsHashCodeAndToStringEvaluator;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.meanbean.extension.MeanBeanExtensions;

/**
 * The unit test class for the class {@link Block}
 */
public class BlockTest
{

	/**
	 * Registers Bouncy Castle before this class reads a PEM key.
	 * <p>
	 * It used to rely on another test class having done it first: run alone, all of these tests
	 * failed with "no such provider: BC", and whether they passed depended on the order the JVM
	 * happened to run classes in (#56). Idempotent, so it does not matter how many classes do it.
	 */
	@BeforeAll
	static void ensureBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private final static byte[] fixedSignature = new byte[] { 48, 44, 2, 20, 89, 48, -114, -49, 36,
			65, 116, -5, 88, 6, -38, -110, -30, -73, 59, -53, 19, -49, 122, 90, 2, 20, 111, 38, 55,
			-120, -125, 17, -66, -8, -121, 85, 31, -82, -80, -31, -33, 116, 121, -90, 123, -113 };

	private Address address;

	@BeforeEach
	public void setUp() throws Exception
	{
		File publickeyPemDir;
		File publickeyPemFile;
		PublicKey publicKey;

		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");
		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		address = new Address("foo", publicKey.getEncoded());
	}

	/**
	 * Test method for {@link Block} constructors
	 */
	@Test
	public final void testConstructors()
	{
		Block block;
		Transaction transaction;
		String text;

		block = new Block();
		assertNotNull(block);
		block.setHash(new byte[] { });

		text = "transaction-name";
		transaction = new Transaction(text, address.getHash(), fixedSignature);

		block = new Block(null, ListFactory.newArrayList(transaction), 4847556);
		assertNotNull(block);
	}

	/**
	 * Test method for {@link Block#equals(Object)}, {@link Block#hashCode()} and
	 * {@link Block#toString()}
	 */
	@Test
	public void testEqualsHashcodeAndToStringWithClass()
	{
		boolean expected;
		boolean actual;

		actual = EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(Block.class);
		expected = true;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link Block} with the MeanBean hashCode and equals testers
	 * <p>
	 * The getter/setter tester is not run on this class: setting {@code data} recomputes the hash
	 * by design (#55), which that tester reports as a side effect, and ignoring the property would
	 * need a fresh MeanBean tester - which breaks the shared MeanBean context of every later class
	 * on the same thread (#61). The round trip of every property is asserted directly in
	 * {@link #testGettersAndSetters()} and the boundary tests below, the effect on the hash by the
	 * #55 tests. In equals, data is significant.
	 */
	@Test
	public void testWithBeanTester()
	{
		MeanBeanExtensions.testWithHashCodeMethodTester(Block.class);
		MeanBeanExtensions.testWithEqualsMethodTester(Block.class);
	}

	/**
	 * Test method for the getters and setters of {@link Block}
	 */
	@Test
	public void testGettersAndSetters()
	{
		Block block = new Block();
		// data first: setting it recomputes the hash (#55), which would overwrite the one set below
		block.setData("Some data");
		block.setHash(new byte[] { 1, 2, 3 });
		block.setMerkleRoot(new byte[] { 4, 5, 6 });
		block.setPreviousBlockHash(new byte[] { 7, 8, 9 });
		block.setTimestamp(123456789L);
		block.setTries(10L);
		List<ITransaction> transactions = new ArrayList<>();
		block.setTransactions(transactions);

		assertSame(transactions, block.getTransactions());
		assertNotNull(block.getHash());
		assertNotNull(block.getMerkleRoot());
		assertNotNull(block.getPreviousBlockHash());
		assertNotNull(block.getTimestamp());
		assertNotNull(block.getTries());
		assertNotNull(block.getData());

		assertEquals("Some data", block.getData());
		assertEquals(123456789L, block.getTimestamp());
		assertEquals(10L, block.getTries());
		assertTrue(Arrays.equals(new byte[] { 1, 2, 3 }, block.getHash()));
		assertTrue(Arrays.equals(new byte[] { 4, 5, 6 }, block.getMerkleRoot()));
		assertTrue(Arrays.equals(new byte[] { 7, 8, 9 }, block.getPreviousBlockHash()));
	}

	/**
	 * Test method for {@link Block#getLeadingZerosCount()}
	 */
	@Test
	public void testGetLeadingZerosCount()
	{
		Block block = new Block();
		block.setHash(new byte[] { 0, 0, 1 });
		assertEquals(2, block.getLeadingZerosCount());

		block.setHash(new byte[] { 1, 2, 3 });
		assertEquals(0, block.getLeadingZerosCount());

		block.setHash(new byte[] { 0, 0, 0 });
		assertEquals(3, block.getLeadingZerosCount());
	}

	/**
	 * Test method for boundary conditions of {@link Block#setHash(byte[])} and
	 * {@link Block#getHash()}
	 */
	@Test
	public void testSetGetHashBoundary()
	{
		Block block = new Block();
		byte[] hash = new byte[0];
		block.setHash(hash);
		assertEquals(hash, block.getHash());

		hash = new byte[256];
		Arrays.fill(hash, (byte)1);
		block.setHash(hash);
		assertEquals(hash, block.getHash());
	}

	/**
	 * Test method for boundary conditions of {@link Block#setMerkleRoot(byte[])} and
	 * {@link Block#getMerkleRoot()}
	 */
	@Test
	public void testSetGetMerkleRootBoundary()
	{
		Block block = new Block();
		byte[] merkleRoot = new byte[0];
		block.setMerkleRoot(merkleRoot);
		assertEquals(merkleRoot, block.getMerkleRoot());

		merkleRoot = new byte[256];
		Arrays.fill(merkleRoot, (byte)1);
		block.setMerkleRoot(merkleRoot);
		assertEquals(merkleRoot, block.getMerkleRoot());
	}

	/**
	 * Test method for boundary conditions of {@link Block#setPreviousBlockHash(byte[])} and
	 * {@link Block#getPreviousBlockHash()}
	 */
	@Test
	public void testSetGetPreviousBlockHashBoundary()
	{
		Block block = new Block();
		byte[] previousBlockHash = new byte[0];
		block.setPreviousBlockHash(previousBlockHash);
		assertEquals(previousBlockHash, block.getPreviousBlockHash());

		previousBlockHash = new byte[256];
		Arrays.fill(previousBlockHash, (byte)1);
		block.setPreviousBlockHash(previousBlockHash);
		assertEquals(previousBlockHash, block.getPreviousBlockHash());
	}

	/**
	 * Test method for boundary conditions of {@link Block#setTimestamp(long)} and
	 * {@link Block#getTimestamp()}
	 */
	@Test
	public void testSetGetTimestampBoundary()
	{
		Block block = new Block();
		block.setTimestamp(Long.MIN_VALUE);
		assertEquals(Long.MIN_VALUE, block.getTimestamp());

		block.setTimestamp(Long.MAX_VALUE);
		assertEquals(Long.MAX_VALUE, block.getTimestamp());
	}

	/**
	 * Test method for boundary conditions of {@link Block#setTries(long)} and
	 * {@link Block#getTries()}
	 */
	@Test
	public void testSetGetTriesBoundary()
	{
		Block block = new Block();
		block.setTries(Long.MIN_VALUE);
		assertEquals(Long.MIN_VALUE, block.getTries());

		block.setTries(Long.MAX_VALUE);
		assertEquals(Long.MAX_VALUE, block.getTries());
	}

	/**
	 * Test method for boundary conditions of {@link Block#setData(String)} and
	 * {@link Block#getData()}
	 */
	@Test
	public void testSetGetDataBoundary()
	{
		Block block = new Block();
		block.setData("");
		assertEquals("", block.getData());

		String longString = new String(new char[256]).replace('\0', 'a');
		block.setData(longString);
		assertEquals(longString, block.getData());
	}

	private static final byte[] PREVIOUS_BLOCK_HASH = "previous-block"
		.getBytes(StandardCharsets.UTF_8);

	private static final long TIMESTAMP = 1_727_654_400_000L;

	private static Block blockWithData(String data)
	{
		return new Block(PREVIOUS_BLOCK_HASH, new ArrayList<ITransaction>(), 7L, TIMESTAMP, data);
	}

	/**
	 * Reproduction of #55: the data of a block used to lie outside its hash, so changing it left
	 * the hash where it was
	 */
	@Test
	public void setDataMovesTheHash()
	{
		Block block = new Block(PREVIOUS_BLOCK_HASH, new ArrayList<ITransaction>(), 1L);
		byte[] hashBefore = block.getHash().clone();

		block.setData("pun: the panopticon is a poor joke");

		assertFalse(Arrays.equals(hashBefore, block.getHash()));
	}

	/**
	 * Two blocks built from the same content, the timestamp included, have the same hash and are
	 * equal - which is what lets a third party recompute a hash it was given
	 */
	@Test
	public void sameContentGivesTheSameHash()
	{
		Block first = blockWithData("the same pun");
		Block second = blockWithData("the same pun");

		assertArrayEquals(first.getHash(), second.getHash());
		assertEquals(first, second);
	}

	/**
	 * A block whose data is set afterwards ends up with the same hash as one that received the data
	 * in its constructor: the hash describes the content, not the order it arrived in
	 */
	@Test
	public void dataFromTheSetterAndFromTheConstructorGiveTheSameHash()
	{
		Block fromConstructor = blockWithData("late pun");
		Block fromSetter = blockWithData(null);

		fromSetter.setData("late pun");

		assertArrayEquals(fromConstructor.getHash(), fromSetter.getHash());
	}

	/**
	 * A block without data keeps the hash it had before data was covered, so existing chains are
	 * not invalidated by the fix
	 */
	@Test
	public void blockWithoutDataKeepsTheHashOverTheOtherFourFields()
	{
		Block block = blockWithData(null);

		byte[] expected = HashExtensions.hash(PREVIOUS_BLOCK_HASH, block.getMerkleRoot(), 7L,
			TIMESTAMP, HashAlgorithm.SHA256);

		assertArrayEquals(expected, block.getHash());
	}

	/**
	 * Equality looks at the data itself, not only at the hash: a block whose hash was set by hand
	 * to that of another block is still not equal to it when the data differs
	 */
	@Test
	public void blocksWithTheSameHashButDifferentDataAreNotEqual()
	{
		Block block = blockWithData("original pun");
		Block forged = blockWithData("forged pun");
		forged.setHash(block.getHash().clone());

		assertFalse(block.equals(forged));
	}

	static Stream<Arguments> differentData()
	{
		return Stream.of(Arguments.of("no data against empty data", null, ""),
			Arguments.of("empty data against one character", "", "a"),
			Arguments.of("one character changed", "pun a", "pun b"), Arguments
				.of("data against the same data plus a trailing zero character", "pun", "pun\0"),
			Arguments.of("non ASCII characters", "\u00e4", "\u00f6"));
	}

	/**
	 * Blocks that differ only in their data differ in their hash and are not equal
	 *
	 * @param caseName
	 *            the name of the case, shown in the report
	 * @param data
	 *            the data of the first block
	 * @param otherData
	 *            the data of the second block
	 */
	@ParameterizedTest(name = "{0}")
	@MethodSource("differentData")
	public void differentDataGivesADifferentHash(String caseName, String data, String otherData)
	{
		Block block = blockWithData(data);
		Block other = blockWithData(otherData);

		assertFalse(Arrays.equals(block.getHash(), other.getHash()));
		assertFalse(block.equals(other));
	}
}
