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
package io.github.astrapi69.crypt.data.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.stream.Stream;

import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;

/**
 * Parameterized tests for the behaviour of {@link PrivateKeyExtensions} with private keys that are
 * neither RSA, DSA nor EC keys
 */
class PrivateKeyExtensionsGenericKeyParameterizedTest
{

	/**
	 * One key pair generator algorithm whose private keys are neither RSA, DSA nor EC keys
	 *
	 * @param algorithm
	 *            the key pair generator algorithm
	 */
	record GenericKeyCase(String algorithm) {
	}

	static Stream<GenericKeyCase> genericKeyCases()
	{
		return Stream.of(new GenericKeyCase("Ed25519"), new GenericKeyCase("X25519"));
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#getKeyLength(PrivateKey)},
	 * {@link PrivateKeyExtensions#getKeySize(PrivateKey)} and
	 * {@link PrivateKeyExtensions#toPemFormat(PrivateKey)} with a generic private key
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if key generation or the pem conversion fails
	 */
	@ParameterizedTest
	@MethodSource("genericKeyCases")
	void genericPrivateKey(final GenericKeyCase testCase) throws Exception
	{
		PrivateKey privateKey = KeyPairGenerator.getInstance(testCase.algorithm()).generateKeyPair()
			.getPrivate();
		assertFalse(privateKey instanceof RSAPrivateKey || privateKey instanceof DSAPrivateKey
			|| privateKey instanceof ECPrivateKey);

		assertEquals(-1, PrivateKeyExtensions.getKeyLength(privateKey));
		assertEquals(KeySize.UNKNOWN, PrivateKeyExtensions.getKeySize(privateKey));

		String pem = PrivateKeyExtensions.toPemFormat(privateKey);
		assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----"), pem);
		PemObject pemObject = PemObjectReader.getPemObject(pem);
		assertEquals(PemType.PRIVATE_KEY.getName(), pemObject.getType());
		assertArrayEquals(PrivateKeyExtensions.toPKCS1Format(privateKey), pemObject.getContent());
	}
}
