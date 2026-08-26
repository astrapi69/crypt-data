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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;

/**
 * Parameterized tests for {@link PrivateKeyExtensions#toPkcs8PemFormat(PrivateKey)} and
 * {@link PrivateKeyExtensions#toPemFormat(PrivateKey)}, the two methods the writer picks between
 * once it knows which format was asked for.
 * <p>
 * They are tested apart from the writer because the defect in issue #12 was that the writer picked
 * the wrong one of the two, which stays invisible as long as only one of them is exercised.
 */
class PrivateKeyExtensionsPemFormatParameterizedTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static PrivateKey newPrivateKey(final String algorithm) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm,
			BouncyCastleProvider.PROVIDER_NAME);
		if ("RSA".equals(algorithm) || "DSA".equals(algorithm))
		{
			generator.initialize(2048);
		}
		return generator.generateKeyPair().getPrivate();
	}

	private static PrivateKey newEcPrivateKey(final String curve) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC",
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(new ECGenParameterSpec(curve));
		return generator.generateKeyPair().getPrivate();
	}

	/**
	 * The pkcs#8 form is the same for every algorithm, because pkcs#8 is what makes them all look
	 * alike: one header, and underneath it exactly the bytes the key hands out.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if key generation or the conversion fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519", "Ed448", "X25519", "DH" })
	void thePkcs8FormIsTheHeaderAndTheEncodingUnderneath(final String algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		String pem = PrivateKeyExtensions.toPkcs8PemFormat(privateKey);

		PemObject pemObject = PemObjectReader.getPemObject(pem);
		assertEquals(PemType.PRIVATE_KEY.getName(), pemObject.getType(),
			algorithm + " must carry the header that names pkcs#8");
		assertArrayEquals(privateKey.getEncoded(), pemObject.getContent(),
			algorithm + " must carry its pkcs#8 encoding unchanged");
	}

	/**
	 * Converting a key does not depend on anything but the key, so asking twice must answer twice
	 * the same. A conversion that reached for a random or a timestamp would show up here.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if key generation or the conversion fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "EC", "Ed25519" })
	void askingTwiceAnswersTwiceTheSame(final String algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		assertEquals(PrivateKeyExtensions.toPkcs8PemFormat(privateKey),
			PrivateKeyExtensions.toPkcs8PemFormat(privateKey));
		assertEquals(PrivateKeyExtensions.toPemFormat(privateKey),
			PrivateKeyExtensions.toPemFormat(privateKey));
	}

	/**
	 * One key algorithm with the pem type its traditional form carries and whether that form is
	 * distinct from the pkcs#8 one
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @param traditionalPemType
	 *            the pem type the traditional form is written under
	 * @param hasATraditionalFormOfItsOwn
	 *            whether the traditional form differs from the pkcs#8 form
	 */
	record TraditionalFormCase(String algorithm, String traditionalPemType,
		boolean hasATraditionalFormOfItsOwn) {
		@Override
		public String toString()
		{
			return algorithm + " traditionally is '" + traditionalPemType + "'";
		}
	}

	static Stream<TraditionalFormCase> traditionalFormCases()
	{
		return Stream.of(new TraditionalFormCase("RSA", PemType.RSA_PRIVATE_KEY.getName(), true),
			new TraditionalFormCase("DSA", PemType.DSA_PRIVATE_KEY.getName(), true),
			new TraditionalFormCase("EC", PemType.EC_PRIVATE_KEY.getName(), true),
			// nothing to strip a wrapper for, so these keep the pkcs#8 form and say so
			new TraditionalFormCase("Ed25519", PemType.PRIVATE_KEY.getName(), false),
			new TraditionalFormCase("Ed448", PemType.PRIVATE_KEY.getName(), false),
			new TraditionalFormCase("X25519", PemType.PRIVATE_KEY.getName(), false),
			new TraditionalFormCase("DH", PemType.PRIVATE_KEY.getName(), false));
	}

	/**
	 * The traditional header comes from what the key is, not from what its bytes happen to look
	 * like. Deciding it from the bytes is what labelled every key an rsa key in issue #12.
	 *
	 * @param testCase
	 *            the algorithm under test with the header it must carry
	 * @throws Exception
	 *             if key generation or the conversion fails
	 */
	@ParameterizedTest
	@MethodSource("traditionalFormCases")
	void theTraditionalHeaderIsChosenByTheKeyAndNotByItsBytes(final TraditionalFormCase testCase)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(testCase.algorithm());

		String pem = PrivateKeyExtensions.toPemFormat(privateKey);

		PemObject pemObject = PemObjectReader.getPemObject(pem);
		assertEquals(testCase.traditionalPemType(), pemObject.getType(), testCase.toString());
		byte[] expectedContent = testCase.hasATraditionalFormOfItsOwn()
			? PrivateKeyExtensions.toPKCS1Format(privateKey)
			: privateKey.getEncoded();
		assertArrayEquals(expectedContent, pemObject.getContent(),
			testCase + ", and the body must be the encoding that header names");
		if (testCase.hasATraditionalFormOfItsOwn())
		{
			assertNotEquals(PrivateKeyExtensions.toPkcs8PemFormat(privateKey), pem,
				testCase.algorithm() + " has a traditional form of its own, so the two forms "
					+ "cannot be the same text");
		}
		else
		{
			assertEquals(PrivateKeyExtensions.toPkcs8PemFormat(privateKey), pem,
				testCase.algorithm() + " has no traditional form, so it keeps the pkcs#8 one");
		}
	}

	/**
	 * The writer and the extension are two ways to the same file, and they must not drift apart -
	 * that they had is the whole of issue #12.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if key generation or writing fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "EC", "Ed25519" })
	void theWriterEmitsExactlyWhatTheExtensionProduces(final String algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm);

		ByteArrayOutputStream asPkcs8 = new ByteArrayOutputStream();
		PrivateKeyWriter.write(privateKey, asPkcs8, KeyFileFormat.PEM, KeyFormat.PKCS_8);
		ByteArrayOutputStream asTraditional = new ByteArrayOutputStream();
		PrivateKeyWriter.write(privateKey, asTraditional, KeyFileFormat.PEM, KeyFormat.PKCS_1);

		assertEquals(PrivateKeyExtensions.toPkcs8PemFormat(privateKey),
			asPkcs8.toString("US-ASCII"),
			algorithm + " as pkcs#8 must be what toPkcs8PemFormat produces");
		assertEquals(PrivateKeyExtensions.toPemFormat(privateKey),
			asTraditional.toString("US-ASCII"),
			algorithm + " as pkcs#1 must be what toPemFormat produces");
	}

	/**
	 * The curve is part of an ec key, so both forms have to carry it: the pkcs#8 one in its
	 * algorithm parameters and the traditional one inside the rfc 5915 structure. A key on the
	 * smallest and on the largest of the usual curves proves the conversion does not depend on a
	 * length it happened to be written for.
	 *
	 * @param curve
	 *            the named curve to generate on
	 * @throws Exception
	 *             if key generation, the conversion or reading back fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "secp256r1", "secp384r1", "secp521r1", "secp256k1" })
	void anEcKeyKeepsItsCurveInBothForms(final String curve) throws Exception
	{
		PrivateKey privateKey = newEcPrivateKey(curve);

		PemObject asPkcs8 = PemObjectReader
			.getPemObject(PrivateKeyExtensions.toPkcs8PemFormat(privateKey));
		assertArrayEquals(privateKey.getEncoded(), asPkcs8.getContent(),
			curve + " must keep its pkcs#8 encoding unchanged");

		String traditional = PrivateKeyExtensions.toPemFormat(privateKey);
		assertTrue(
			traditional.startsWith("-----BEGIN " + PemType.EC_PRIVATE_KEY.getName() + "-----"),
			curve + " must be written under the ec header");
		PEMKeyPair parsed = (PEMKeyPair)new PEMParser(new StringReader(traditional)).readObject();
		PrivateKey readBack = new JcaPEMKeyConverter()
			.setProvider(BouncyCastleProvider.PROVIDER_NAME).getKeyPair(parsed).getPrivate();
		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			curve + " must come back off its traditional form as the same key, curve included");
	}

	/** Neither conversion has anything to answer for a key that is not there. */
	@ParameterizedTest
	@ValueSource(strings = { "toPkcs8PemFormat", "toPemFormat", "toPKCS1Format" })
	void aMissingKeyIsRefusedRatherThanConverted(final String method)
	{
		assertThrows(NullPointerException.class, () -> {
			switch (method)
			{
				case "toPkcs8PemFormat" -> PrivateKeyExtensions.toPkcs8PemFormat(null);
				case "toPemFormat" -> PrivateKeyExtensions.toPemFormat(null);
				default -> PrivateKeyExtensions.toPKCS1Format(null);
			}
		});
	}
}
