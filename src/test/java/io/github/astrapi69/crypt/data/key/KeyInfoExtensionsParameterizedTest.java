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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.function.Function;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.model.KeyInfo;

/**
 * Parameterized tests for the key type guards and the round trips of {@link KeyInfoExtensions}
 */
class KeyInfoExtensionsParameterizedTest
{

	private static KeyPair keyPair;

	/**
	 * One conversion of a {@link KeyInfo} with the wrong key type
	 *
	 * @param description
	 *            what is converted
	 * @param keyType
	 *            the (wrong) key type display value of the info
	 * @param conversion
	 *            the conversion under test
	 * @param expectedMessagePart
	 *            the text the exception message must contain
	 */
	record WrongKeyTypeCase(String description, String keyType,
		Function<KeyInfo, Object> conversion, String expectedMessagePart) {
	}

	/**
	 * One conversion
	 *
	 * @param description
	 *            the conversion name
	 * @param conversion
	 *            the conversion under test
	 */
	record ConversionCase(String description, Function<KeyInfo, Object> conversion) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 1024);
	}

	static Stream<WrongKeyTypeCase> wrongKeyTypeCases()
	{
		return Stream.of(
			new WrongKeyTypeCase("public key info to private key",
				KeyType.PUBLIC_KEY.getDisplayValue(), KeyInfoExtensions::toPrivateKey,
				"is not a private key"),
			new WrongKeyTypeCase("certificate info to private key",
				KeyType.CERTIFICATE.getDisplayValue(), KeyInfoExtensions::toPrivateKey,
				"is not a private key"),
			new WrongKeyTypeCase("unknown key type to private key", "no such key type",
				KeyInfoExtensions::toPrivateKey, "is not a private key"),
			new WrongKeyTypeCase("private key info to public key",
				KeyType.PRIVATE_KEY.getDisplayValue(), KeyInfoExtensions::toPublicKey,
				"is not a public key"),
			new WrongKeyTypeCase("certificate info to public key",
				KeyType.CERTIFICATE.getDisplayValue(), KeyInfoExtensions::toPublicKey,
				"is not a public key"),
			new WrongKeyTypeCase("private key info to certificate",
				KeyType.PRIVATE_KEY.getDisplayValue(), KeyInfoExtensions::toX509Certificate,
				"is not a X509Certificate"),
			new WrongKeyTypeCase("public key info to certificate",
				KeyType.PUBLIC_KEY.getDisplayValue(), KeyInfoExtensions::toX509Certificate,
				"is not a X509Certificate"));
	}

	/**
	 * Test method for the key type guards of {@link KeyInfoExtensions#toPrivateKey(KeyInfo)},
	 * {@link KeyInfoExtensions#toPublicKey(KeyInfo)} and
	 * {@link KeyInfoExtensions#toX509Certificate(KeyInfo)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("wrongKeyTypeCases")
	void rejectsWrongKeyType(final WrongKeyTypeCase testCase)
	{
		KeyInfo keyInfo = KeyInfo.builder().keyType(testCase.keyType())
			.encoded(keyPair.getPrivate().getEncoded()).algorithm("RSA").build();

		RuntimeException actual = assertThrows(RuntimeException.class,
			() -> testCase.conversion().apply(keyInfo), testCase.description());

		assertTrue(actual.getMessage().contains(testCase.expectedMessagePart()),
			actual.getMessage());
		assertTrue(actual.getMessage().contains(keyInfo.toString()), actual.getMessage());
	}

	static Stream<ConversionCase> conversionCases()
	{
		return Stream.of(new ConversionCase("toPrivateKey", KeyInfoExtensions::toPrivateKey),
			new ConversionCase("toPublicKey", KeyInfoExtensions::toPublicKey),
			new ConversionCase("toX509Certificate", KeyInfoExtensions::toX509Certificate));
	}

	/**
	 * Test method for the non-null contract of the conversions
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("conversionCases")
	void rejectsNull(final ConversionCase testCase)
	{
		assertThrows(NullPointerException.class, () -> testCase.conversion().apply(null),
			testCase.description());
	}

	/**
	 * Test method for the round trip {@link KeyInfoExtensions#toKeyInfo(java.security.PrivateKey)}
	 * to {@link KeyInfoExtensions#toPrivateKey(KeyInfo)} and the public key counterpart
	 */
	@Test
	void keyInfoRoundTrip()
	{
		KeyInfo privateKeyInfo = KeyInfoExtensions.toKeyInfo(keyPair.getPrivate());
		KeyInfo publicKeyInfo = KeyInfoExtensions.toKeyInfo(keyPair.getPublic());

		assertEquals(KeyType.PRIVATE_KEY.getDisplayValue(), privateKeyInfo.getKeyType());
		assertEquals(KeyType.PUBLIC_KEY.getDisplayValue(), publicKeyInfo.getKeyType());
		assertEquals(keyPair.getPrivate(), KeyInfoExtensions.toPrivateKey(privateKeyInfo));
		assertEquals(keyPair.getPublic(), KeyInfoExtensions.toPublicKey(publicKeyInfo));
	}
}
