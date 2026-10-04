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
package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for {@link SignatureFactory#verify(PublicKey, String, byte[], byte[])} with
 * structurally malformed signatures, i.e. byte arrays the underlying {@link Signature} rejects with
 * a {@link SignatureException} rather than a plain verification failure
 */
class SignatureFactoryMalformedSignatureParameterizedTest
{

	private static final byte[] DATA = "the quick brown fox jumps over the lazy dog"
		.getBytes(StandardCharsets.UTF_8);

	private static KeyPair ed25519;
	private static KeyPair ecP256;

	/**
	 * One malformed signature
	 *
	 * @param description
	 *            what is malformed
	 * @param algorithm
	 *            the signature algorithm
	 * @param signature
	 *            the malformed signature bytes
	 */
	record MalformedSignatureCase(String description, String algorithm, byte[] signature) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		ed25519 = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
		KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
		ecGenerator.initialize(256);
		ecP256 = ecGenerator.generateKeyPair();
	}

	static Stream<MalformedSignatureCase> malformedSignatureCases()
	{
		byte[] tooLong = new byte[65];
		Arrays.fill(tooLong, (byte)0x01);
		return Stream.of(
			new MalformedSignatureCase("empty Ed25519 signature", "Ed25519", new byte[0]),
			new MalformedSignatureCase("one byte Ed25519 signature", "Ed25519",
				new byte[] { 0x2a }),
			new MalformedSignatureCase("65 byte Ed25519 signature", "Ed25519", tooLong),
			new MalformedSignatureCase("empty ECDSA signature", "SHA256withECDSA", new byte[0]),
			new MalformedSignatureCase("non-DER ECDSA signature", "SHA256withECDSA",
				new byte[] { (byte)0xff, 0x00, 0x01 }));
	}

	private static PublicKey publicKeyFor(final String algorithm)
	{
		return "Ed25519".equals(algorithm) ? ed25519.getPublic() : ecP256.getPublic();
	}

	/**
	 * Test method for {@link SignatureFactory#verify(PublicKey, String, byte[], byte[])}: a
	 * malformed signature is reported as not verified instead of propagating the
	 * {@link SignatureException} the JCA throws for it
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the signature object cannot be created
	 */
	@ParameterizedTest
	@MethodSource("malformedSignatureCases")
	void verifyReturnsFalseForMalformedSignature(final MalformedSignatureCase testCase)
		throws Exception
	{
		PublicKey publicKey = publicKeyFor(testCase.algorithm());

		// precondition: the raw JCA verification really rejects these bytes with an exception
		Signature raw = Signature.getInstance(testCase.algorithm());
		raw.initVerify(publicKey);
		raw.update(DATA);
		boolean rawThrows;
		try
		{
			raw.verify(testCase.signature());
			rawThrows = false;
		}
		catch (SignatureException signatureException)
		{
			rawThrows = true;
		}
		assertTrue(rawThrows, testCase.description() + " must be rejected by the JCA");

		boolean actual = SignatureFactory.verify(publicKey, testCase.algorithm(), DATA,
			testCase.signature());

		assertFalse(actual, testCase.description());
	}
}
