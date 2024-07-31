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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import com.google.common.primitives.Longs;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;

/**
 * The unit test class for the class {@link HashExtensions}
 */
public class HashExtensionsTest
{

	/**
	 * Test method for {@link HashExtensions#hash(String, String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails
	 */
	@Test
	public void testHash() throws NoSuchAlgorithmException
	{
		String actual;
		String expected;
		Charset charset;
		String password;
		String newInsertPassword;
		String salt;
		HashAlgorithm hashAlgorithm;

		charset = StandardCharsets.UTF_8;
		password = "abcdefghijklmnopqrst";
		newInsertPassword = "abcdefghijklmnopqrst";
		salt = "NzeCdmaz";
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = HashExtensions.hash(password, salt, hashAlgorithm, charset);
		actual = HashExtensions.hash(newInsertPassword, salt, hashAlgorithm, charset);

		assertTrue(expected.equals(actual));
	}

	/**
	 * Test method for {@link HashExtensions#hashAndBase64(String, String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails
	 */
	@Test
	public void testHashAndBase64() throws NoSuchAlgorithmException
	{
		String actual;
		String expected;
		Charset charset;
		String password;
		String newInsertPassword;
		String salt;
		HashAlgorithm hashAlgorithm;

		charset = StandardCharsets.UTF_8;
		password = "secret";
		newInsertPassword = "secret";
		salt = "NzeCdmaz";
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = HashExtensions.hashAndBase64(password, salt, hashAlgorithm, charset);
		actual = HashExtensions.hashAndBase64(newInsertPassword, salt, hashAlgorithm, charset);
		assertTrue(expected.equals(actual));
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails
	 */
	@Test
	public void testHashByteArray() throws NoSuchAlgorithmException
	{
		byte[] actual;
		byte[] expected;
		Charset charset;
		String password;
		String newInsertPassword;
		String salt;
		HashAlgorithm hashAlgorithm;

		charset = StandardCharsets.UTF_8;
		password = "abcdefghijklmnopqrst";
		newInsertPassword = "abcdefghijklmnopqrst";
		salt = "NzeCdmaz";
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = HashExtensions.hash(password.getBytes(), salt, hashAlgorithm, charset);
		actual = HashExtensions.hash(newInsertPassword.getBytes(), salt, hashAlgorithm, charset);

		assertTrue(expected.length == actual.length);
		assertTrue(Arrays.equals(expected, actual));

		expected = HashExtensions.hash(password.getBytes(), null, hashAlgorithm, charset);
		actual = HashExtensions.hash(newInsertPassword.getBytes(), null, hashAlgorithm, charset);

		assertTrue(expected.length == actual.length);
		assertTrue(Arrays.equals(expected, actual));
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], HashAlgorithm)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails
	 */
	@Test
	public void testHashByteArrayWithAlgorithm() throws NoSuchAlgorithmException
	{
		byte[] actual;
		byte[] expected;
		String password;
		String newInsertPassword;
		HashAlgorithm hashAlgorithm;

		password = "abcdefghijklmnopqrst";
		newInsertPassword = "abcdefghijklmnopqrst";
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = HashExtensions.hash(password.getBytes(), hashAlgorithm);
		actual = HashExtensions.hash(newInsertPassword.getBytes(), hashAlgorithm);

		assertTrue(expected.length == actual.length);
		assertTrue(Arrays.equals(expected, actual));
	}

	/**
	 * Test method for {@link HashExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(HashExtensions.class);
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)}
	 */
	@Test
	public void testGetMerkleRootHashSHA_256() throws NoSuchAlgorithmException
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha256("leaf1"));
		hashQueue.add(DigestUtils.sha256("leaf2"));
		hashQueue.add(DigestUtils.sha256("leaf3"));
		hashQueue.add(DigestUtils.sha256("leaf4"));

		HashAlgorithm algorithm = HashAlgorithm.SHA_256;
		byte[] expectedHash = DigestUtils.sha256(ArrayUtils.addAll(
			DigestUtils.sha256(
				ArrayUtils.addAll(DigestUtils.sha256("leaf1"), DigestUtils.sha256("leaf2"))),
			DigestUtils.sha256(
				ArrayUtils.addAll(DigestUtils.sha256("leaf3"), DigestUtils.sha256("leaf4")))));
		byte[] actualHash = HashExtensions.getMerkleRootHash(hashQueue, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)} with SHA1
	 */
	@Test
	public void testGetMerkleRootHashSHA1()
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha1("leaf1"));
		hashQueue.add(DigestUtils.sha1("leaf2"));
		hashQueue.add(DigestUtils.sha1("leaf3"));
		hashQueue.add(DigestUtils.sha1("leaf4"));

		HashAlgorithm algorithm = HashAlgorithm.SHA1;
		byte[] expectedHash = DigestUtils.sha1(ArrayUtils.addAll(
			DigestUtils
				.sha1(ArrayUtils.addAll(DigestUtils.sha1("leaf1"), DigestUtils.sha1("leaf2"))),
			DigestUtils
				.sha1(ArrayUtils.addAll(DigestUtils.sha1("leaf3"), DigestUtils.sha1("leaf4")))));
		byte[] actualHash = HashExtensions.getMerkleRootHash(hashQueue, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)} with SHA_1
	 */
	@Test
	public void testGetMerkleRootHashSHA_1()
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha1("leaf1"));
		hashQueue.add(DigestUtils.sha1("leaf2"));
		hashQueue.add(DigestUtils.sha1("leaf3"));
		hashQueue.add(DigestUtils.sha1("leaf4"));

		HashAlgorithm algorithm = HashAlgorithm.SHA_1;
		byte[] expectedHash = DigestUtils.sha1(ArrayUtils.addAll(
			DigestUtils
				.sha1(ArrayUtils.addAll(DigestUtils.sha1("leaf1"), DigestUtils.sha1("leaf2"))),
			DigestUtils
				.sha1(ArrayUtils.addAll(DigestUtils.sha1("leaf3"), DigestUtils.sha1("leaf4")))));
		byte[] actualHash = HashExtensions.getMerkleRootHash(hashQueue, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)} with SHA384
	 */
	@Test
	public void testGetMerkleRootHashSHA384()
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha384("leaf1"));
		hashQueue.add(DigestUtils.sha384("leaf2"));
		hashQueue.add(DigestUtils.sha384("leaf3"));
		hashQueue.add(DigestUtils.sha384("leaf4"));

		HashAlgorithm algorithm = HashAlgorithm.SHA384;
		byte[] expectedHash = DigestUtils.sha384(ArrayUtils.addAll(
			DigestUtils.sha384(
				ArrayUtils.addAll(DigestUtils.sha384("leaf1"), DigestUtils.sha384("leaf2"))),
			DigestUtils.sha384(
				ArrayUtils.addAll(DigestUtils.sha384("leaf3"), DigestUtils.sha384("leaf4")))));
		byte[] actualHash = HashExtensions.getMerkleRootHash(hashQueue, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)} with SHA_384
	 */
	@Test
	public void testGetMerkleRootHashSHA_384()
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha384("leaf1"));
		hashQueue.add(DigestUtils.sha384("leaf2"));
		hashQueue.add(DigestUtils.sha384("leaf3"));
		hashQueue.add(DigestUtils.sha384("leaf4"));

		HashAlgorithm algorithm = HashAlgorithm.SHA_384;
		byte[] expectedHash = DigestUtils.sha384(ArrayUtils.addAll(
			DigestUtils.sha384(
				ArrayUtils.addAll(DigestUtils.sha384("leaf1"), DigestUtils.sha384("leaf2"))),
			DigestUtils.sha384(
				ArrayUtils.addAll(DigestUtils.sha384("leaf3"), DigestUtils.sha384("leaf4")))));
		byte[] actualHash = HashExtensions.getMerkleRootHash(hashQueue, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)} with SHA512
	 */
	@Test
	public void testGetMerkleRootHashSHA512()
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha512("leaf1"));
		hashQueue.add(DigestUtils.sha512("leaf2"));
		hashQueue.add(DigestUtils.sha512("leaf3"));
		hashQueue.add(DigestUtils.sha512("leaf4"));

		HashAlgorithm algorithm = HashAlgorithm.SHA512;
		byte[] expectedHash = DigestUtils.sha512(ArrayUtils.addAll(
			DigestUtils.sha512(
				ArrayUtils.addAll(DigestUtils.sha512("leaf1"), DigestUtils.sha512("leaf2"))),
			DigestUtils.sha512(
				ArrayUtils.addAll(DigestUtils.sha512("leaf3"), DigestUtils.sha512("leaf4")))));
		byte[] actualHash = HashExtensions.getMerkleRootHash(hashQueue, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)} with SHA_512
	 */
	@Test
	public void testGetMerkleRootHashSHA_512()
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha512("leaf1"));
		hashQueue.add(DigestUtils.sha512("leaf2"));
		hashQueue.add(DigestUtils.sha512("leaf3"));
		hashQueue.add(DigestUtils.sha512("leaf4"));

		HashAlgorithm algorithm = HashAlgorithm.SHA_512;
		byte[] expectedHash = DigestUtils.sha512(ArrayUtils.addAll(
			DigestUtils.sha512(
				ArrayUtils.addAll(DigestUtils.sha512("leaf1"), DigestUtils.sha512("leaf2"))),
			DigestUtils.sha512(
				ArrayUtils.addAll(DigestUtils.sha512("leaf3"), DigestUtils.sha512("leaf4")))));
		byte[] actualHash = HashExtensions.getMerkleRootHash(hashQueue, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)} with null
	 * algorithm
	 */
	@Test
	public void testGetMerkleRootHashWithNullAlgorithm()
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha256("leaf1"));
		hashQueue.add(DigestUtils.sha256("leaf2"));

		assertThrows(NullPointerException.class,
			() -> HashExtensions.getMerkleRootHash(hashQueue, null));
	}

	/**
	 * Test method for {@link HashExtensions#getMerkleRootHash(Queue, HashAlgorithm)} with UNKNOWN
	 * algorithm
	 */
	@Test
	public void testGetMerkleRootHashWithUnknownAlgorithm()
	{
		Queue<byte[]> hashQueue = new LinkedList<>();
		hashQueue.add(DigestUtils.sha256("leaf1"));
		hashQueue.add(DigestUtils.sha256("leaf2"));
		hashQueue.add(DigestUtils.sha256("leaf3"));
		hashQueue.add(DigestUtils.sha256("leaf4"));

		HashAlgorithm algorithm = HashAlgorithm.UNKNOWN;
		byte[] expectedHash = DigestUtils.sha256(ArrayUtils.addAll(
			DigestUtils.sha256(
				ArrayUtils.addAll(DigestUtils.sha256("leaf1"), DigestUtils.sha256("leaf2"))),
			DigestUtils.sha256(
				ArrayUtils.addAll(DigestUtils.sha256("leaf3"), DigestUtils.sha256("leaf4")))));
		byte[] actualHash = HashExtensions.getMerkleRootHash(hashQueue, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersSHA1()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.SHA1;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha1(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersSHA_1()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.SHA_1;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha1(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersSHA256()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.SHA256;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha256(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersSHA_256()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.SHA_256;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha256(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersSHA384()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.SHA384;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha384(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersSHA_384()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.SHA_384;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha384(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersSHA512()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.SHA512;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha512(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersSHA_512()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.SHA_512;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha512(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], byte[], long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithAllParametersDefault()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
		long timestamp = 1234567890L;
		HashAlgorithm algorithm = HashAlgorithm.UNKNOWN; // An unsupported algorithm to trigger the
															// default case

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha256(hashValue); // Default case uses SHA256
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureSHA1()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.SHA1;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha1(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureSHA_1()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.SHA_1;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha1(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureSHA256()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.SHA256;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha256(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureSHA_256()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.SHA_256;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha256(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureSHA384()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.SHA384;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha384(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureSHA_384()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.SHA_384;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha384(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureSHA512()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.SHA512;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha512(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureSHA_512()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.SHA_512;

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha512(hashValue);
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], long, long, HashAlgorithm)}
	 */
	@Test
	public void testHashWithLongSignatureDefault()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] hash = "hash".getBytes(StandardCharsets.UTF_8);
		long signature = 1234567890L;
		long timestamp = 9876543210L;
		HashAlgorithm algorithm = HashAlgorithm.UNKNOWN; // An unsupported algorithm to trigger the
															// default case

		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		byte[] expectedHash = DigestUtils.sha256(hashValue); // Default case uses SHA256
		byte[] actualHash = HashExtensions.hash(input, hash, signature, timestamp, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeySHA1()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.SHA1;

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha1(hashValue);
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeySHA_1()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.SHA_1;

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha1(hashValue);
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeySHA256()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.SHA256;

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha256(hashValue);
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeySHA_256()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.SHA_256;

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha256(hashValue);
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeySHA384()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.SHA384;

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha384(hashValue);
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeySHA_384()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.SHA_384;

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha384(hashValue);
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeySHA512()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.SHA512;

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha512(hashValue);
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeySHA_512()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.SHA_512;

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha512(hashValue);
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], byte[], HashAlgorithm)}
	 */
	@Test
	public void testHashWithPublicKeyDefault()
	{
		byte[] input = "input".getBytes(StandardCharsets.UTF_8);
		byte[] publicKey = "publicKey".getBytes(StandardCharsets.UTF_8);
		HashAlgorithm algorithm = HashAlgorithm.UNKNOWN; // An unsupported algorithm to trigger the
															// default case

		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		byte[] expectedHash = DigestUtils.sha256(hashValue); // Default case uses SHA256
		byte[] actualHash = HashExtensions.hash(input, publicKey, algorithm);

		assertArrayEquals(expectedHash, actualHash);
	}

}
