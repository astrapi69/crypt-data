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
package io.github.astrapi69.crypt.data.hash;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;

/**
 * Tests for {@link HashExtensions#merkleTreeHash(List, HashAlgorithm)}, the Merkle Tree Hash of RFC
 * 6962 section 2.1 (#68)
 */
class MerkleTreeHashTest
{

	/**
	 * The eight leaves of the Certificate Transparency reference test, in hexadecimal
	 */
	private static final List<String> REFERENCE_LEAVES = List.of("", "00", "10", "2021", "3031",
		"40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f");

	static Stream<Arguments> referenceRoots()
	{
		return Stream.of(
			Arguments.of(1, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
			Arguments.of(2, "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
			Arguments.of(3, "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"),
			Arguments.of(4, "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
			Arguments.of(5, "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4"),
			Arguments.of(6, "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef"),
			Arguments.of(7, "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"),
			Arguments.of(8, "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"));
	}

	/**
	 * The roots of the first n reference leaves, as the Certificate Transparency reference
	 * implementation computes them - including the unbalanced trees of 3, 5, 6 and 7 leaves
	 *
	 * @param leafCount
	 *            how many of the reference leaves the tree holds
	 * @param expectedRoot
	 *            the reference root in hexadecimal
	 */
	@ParameterizedTest(name = "{0} leaves")
	@MethodSource("referenceRoots")
	void theRootMatchesTheReferenceVectors(int leafCount, String expectedRoot)
	{
		List<byte[]> leaves = REFERENCE_LEAVES.subList(0, leafCount).stream()
			.map(HexFormat.of()::parseHex).collect(Collectors.toList());

		byte[] root = HashExtensions.merkleTreeHash(leaves, HashAlgorithm.SHA_256);

		assertEquals(expectedRoot, HexFormat.of().formatHex(root));
	}

	/**
	 * The empty tree has the hash of the empty string, not null (RFC 6962: MTH({}) = HASH())
	 */
	@Test
	void theEmptyTreeHasTheHashOfNothing()
	{
		assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", HexFormat
			.of().formatHex(HashExtensions.merkleTreeHash(List.of(), HashAlgorithm.SHA_256)));
	}

	/**
	 * The classic second preimage fails: each forged leaf is the concatenation of two child hashes,
	 * which without domain separation hashes exactly like the inner node above them. The leaf and
	 * node prefixes of RFC 6962 are what tells the two apart (#68)
	 */
	@Test
	void concatenatedChildHashesPresentedAsLeavesDoNotReproduceTheRoot()
	{
		List<byte[]> leaves = leaves("a", "b", "c", "d");
		byte[] root = HashExtensions.merkleTreeHash(leaves, HashAlgorithm.SHA_256);

		List<byte[]> forgedLeaves = List.of(
			concat(leafHash(leaves.get(0)), leafHash(leaves.get(1))),
			concat(leafHash(leaves.get(2)), leafHash(leaves.get(3))));
		byte[] forged = HashExtensions.merkleTreeHash(forgedLeaves, HashAlgorithm.SHA_256);

		assertFalse(Arrays.equals(root, forged));
	}

	private static byte[] leafHash(byte[] leaf)
	{
		return HashExtensions.merkleTreeHash(List.of(leaf), HashAlgorithm.SHA_256);
	}

	private static byte[] concat(byte[] first, byte[] second)
	{
		byte[] joined = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, joined, first.length, second.length);
		return joined;
	}

	/**
	 * Why {@link HashExtensions#getMerkleRootHash} is deprecated rather than changed: over four
	 * leaves and over the two inner nodes above them it gives the same root. Changing it would
	 * change every existing {@code Block} hash, so this pins the behaviour it keeps (#68)
	 */
	@Test
	@SuppressWarnings("deprecation")
	void theDeprecatedMethodCannotTellLeavesFromInnerNodes()
	{
		List<byte[]> leaves = leaves("a", "b", "c", "d");
		byte[] left = HashExtensions.getMerkleRootHash(new LinkedList<>(leaves.subList(0, 2)),
			HashAlgorithm.SHA256);
		byte[] right = HashExtensions.getMerkleRootHash(new LinkedList<>(leaves.subList(2, 4)),
			HashAlgorithm.SHA256);

		byte[] root = HashExtensions.getMerkleRootHash(new LinkedList<>(leaves),
			HashAlgorithm.SHA256);
		byte[] forged = HashExtensions.getMerkleRootHash(new LinkedList<>(List.of(left, right)),
			HashAlgorithm.SHA256);

		assertArrayEquals(root, forged);
	}

	/**
	 * The caller's list is read, not consumed
	 */
	@Test
	void theLeavesAreNotModified()
	{
		List<byte[]> leaves = new ArrayList<>(leaves("a", "b", "c"));
		List<byte[]> copy = new ArrayList<>(leaves);

		HashExtensions.merkleTreeHash(leaves, HashAlgorithm.SHA_256);

		assertEquals(copy, leaves);
	}

	/**
	 * The two spellings of an algorithm in the enum give the same tree
	 *
	 * @param algorithm
	 *            the hash algorithm
	 */
	@ParameterizedTest
	@EnumSource(value = HashAlgorithm.class, names = { "SHA256", "SHA_256", "SHA384", "SHA_384",
			"SHA512", "SHA_512" })
	void everySpellingOfAnAlgorithmIsAccepted(HashAlgorithm algorithm)
	{
		byte[] root = HashExtensions.merkleTreeHash(leaves("a", "b", "c"), algorithm);

		assertEquals(Integer.parseInt(algorithm.name().replaceAll("\\D", "")) / 8, root.length);
	}

	/**
	 * A hash algorithm the platform has no digest for is refused with its name
	 */
	@Test
	void anAlgorithmWithoutADigestIsRefused()
	{
		IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
			() -> HashExtensions.merkleTreeHash(leaves("a"), HashAlgorithm.UNKNOWN));

		assertEquals(true, refusal.getMessage().contains("UNKNOWN"), refusal.getMessage());
	}

	private static List<byte[]> leaves(String... values)
	{
		return Arrays.stream(values).map(String::getBytes).collect(Collectors.toList());
	}
}
