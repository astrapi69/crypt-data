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
package io.github.astrapi69.crypt.data.key.reader;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for {@link PrivateKeyReader#getPrivateKey(byte[])} and
 * {@link PrivateKeyReader#readPrivateKey(byte[])} with byte arrays that are not a PKCS#8 encoded
 * key of any of the probed algorithms (DiffieHellman, DSA, EC, RSASSA-PSS, RSA)
 */
class PrivateKeyReaderUnreadableBytesParameterizedTest
{

	/**
	 * One unreadable byte array
	 *
	 * @param description
	 *            what the bytes are
	 * @param bytes
	 *            the bytes
	 */
	record UnreadableBytesCase(String description, byte[] bytes) {
	}

	static Stream<UnreadableBytesCase> unreadableBytesCases()
	{
		byte[] pattern = new byte[128];
		for (int i = 0; i < pattern.length; i++)
		{
			pattern[i] = (byte)i;
		}
		return Stream.of(new UnreadableBytesCase("empty", new byte[0]),
			new UnreadableBytesCase("single byte", new byte[] { 0x30 }),
			new UnreadableBytesCase("ascii text",
				"this is not a private key".getBytes(StandardCharsets.US_ASCII)),
			new UnreadableBytesCase("counting pattern", pattern));
	}

	/**
	 * Test method for {@link PrivateKeyReader#getPrivateKey(byte[])} and
	 * {@link PrivateKeyReader#readPrivateKey(byte[])}: bytes that match no algorithm yield an empty
	 * {@link Optional} respectively {@code null} instead of an exception
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("unreadableBytesCases")
	void unreadableBytesYieldNoPrivateKey(final UnreadableBytesCase testCase)
	{
		Optional<PrivateKey> actual = PrivateKeyReader.getPrivateKey(testCase.bytes());

		assertFalse(actual.isPresent(), testCase.description());
		assertNull(PrivateKeyReader.readPrivateKey(testCase.bytes()), testCase.description());
	}

	/**
	 * Counter example to the cases above: a real PKCS#8 encoding of the last probed algorithm (RSA)
	 * is found, so the empty result is really caused by the bytes and not by the probing order
	 *
	 * @throws Exception
	 *             if the key pair cannot be generated
	 */
	@Test
	void rsaBytesAreReadAsLastProbedAlgorithm() throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		PrivateKey expected = generator.generateKeyPair().getPrivate();

		Optional<PrivateKey> actual = PrivateKeyReader.getPrivateKey(expected.getEncoded());

		assertTrue(actual.isPresent());
		assertTrue("RSA".equals(actual.get().getAlgorithm()));
	}
}
