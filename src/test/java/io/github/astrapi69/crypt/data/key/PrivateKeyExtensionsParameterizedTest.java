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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

/**
 * The parameterized test class for the class {@link PrivateKeyExtensions}
 */
public class PrivateKeyExtensionsParameterizedTest
{

	/**
	 * Parameterized test method for {@link PrivateKeyExtensions#getAlgorithm(byte[])}
	 *
	 * @param oid
	 *            the algorithm OID
	 * @param expectedAlgorithm
	 *            the expected algorithm name
	 * @throws Exception
	 *             if an error occurs
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/algorithm-oids.csv", numLinesToSkip = 1)
	public void testGetAlgorithmParameterized(String oid, String expectedAlgorithm) throws Exception
	{
		byte[] privateKeyBytes = createDummyPrivateKeyBytes(oid);
		String algorithm = PrivateKeyExtensions.getAlgorithm(privateKeyBytes);

		assertEquals(expectedAlgorithm, algorithm);
	}

	/**
	 * Creates a dummy private key bytes for a given OID
	 *
	 * @param oid
	 *            the OID
	 * @return the dummy private key bytes
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	private byte[] createDummyPrivateKeyBytes(String oid) throws IOException
	{
		ASN1ObjectIdentifier objectIdentifier = new ASN1ObjectIdentifier(oid);
		AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(objectIdentifier);
		PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(algorithmIdentifier, objectIdentifier);
		return privateKeyInfo.getEncoded();
	}
}
