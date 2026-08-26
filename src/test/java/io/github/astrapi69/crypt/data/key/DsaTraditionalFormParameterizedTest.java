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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;

/**
 * Regression tests for issue #15: a dsa key written in its traditional form carried its private
 * exponent alone.
 * <p>
 * A dsa key is a number in a group, and the group is p, q and g. Those live in the algorithm
 * identifier of the pkcs#8 wrapper, so stripping the wrapper - which is what the traditional form
 * of an rsa or an ec key amounts to - dropped them. What was left was a number no reader could make
 * a key out of again.
 */
class DsaTraditionalFormParameterizedTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static DSAPrivateKey newDsaPrivateKey(final int keySize) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA",
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(keySize);
		return (DSAPrivateKey)generator.generateKeyPair().getPrivate();
	}

	/**
	 * The traditional dsa structure is SEQUENCE { version, p, q, g, y, x }. Every one of those has
	 * to be there and has to be the key's own, or what is written is a different key.
	 *
	 * @param keySize
	 *            the key size to generate with
	 * @throws Exception
	 *             if key generation or the conversion fails
	 */
	@ParameterizedTest
	@ValueSource(ints = { 1024, 2048 })
	void theTraditionalFormCarriesTheWholeGroupAndNotOnlyTheSecret(final int keySize)
		throws Exception
	{
		DSAPrivateKey privateKey = newDsaPrivateKey(keySize);

		ASN1Primitive structure = ASN1Primitive
			.fromByteArray(PrivateKeyExtensions.toPKCS1Format(privateKey));

		assertTrue(structure instanceof ASN1Sequence,
			"the traditional dsa form is a sequence, but was a "
				+ structure.getClass().getSimpleName()
				+ " - the private exponent on its own is what issue #15 was about");
		ASN1Sequence sequence = (ASN1Sequence)structure;
		assertEquals(6, sequence.size(),
			"the sequence is version, p, q, g, y and x, but held " + sequence.size() + " elements");
		assertEquals(BigInteger.ZERO, ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue(),
			"the version of the traditional dsa structure is 0");
		assertEquals(privateKey.getParams().getP(),
			ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue(), "p must be the key's own");
		assertEquals(privateKey.getParams().getQ(),
			ASN1Integer.getInstance(sequence.getObjectAt(2)).getValue(), "q must be the key's own");
		assertEquals(privateKey.getParams().getG(),
			ASN1Integer.getInstance(sequence.getObjectAt(3)).getValue(), "g must be the key's own");
		assertEquals(privateKey.getX(), ASN1Integer.getInstance(sequence.getObjectAt(5)).getValue(),
			"x must be the key's own");
	}

	/**
	 * The public value in the structure is the one that belongs to the private one, because a
	 * reader that takes y at face value would otherwise hand out a key pair that does not match.
	 *
	 * @param keySize
	 *            the key size to generate with
	 * @throws Exception
	 *             if key generation or the conversion fails
	 */
	@ParameterizedTest
	@ValueSource(ints = { 1024, 2048 })
	void thePublicValueInTheStructureBelongsToThePrivateOne(final int keySize) throws Exception
	{
		DSAPrivateKey privateKey = newDsaPrivateKey(keySize);

		ASN1Sequence sequence = (ASN1Sequence)ASN1Primitive
			.fromByteArray(PrivateKeyExtensions.toPKCS1Format(privateKey));

		BigInteger y = ASN1Integer.getInstance(sequence.getObjectAt(4)).getValue();
		assertEquals(
			privateKey.getParams().getG().modPow(privateKey.getX(), privateKey.getParams().getP()),
			y, "y has to be g raised to x, modulo p");
	}

	/**
	 * The point of all of it: the written file is a dsa key again when it is read.
	 *
	 * @param keySize
	 *            the key size to generate with
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if writing or reading fails
	 */
	@ParameterizedTest
	@ValueSource(ints = { 1024, 2048 })
	void aDsaKeyWrittenTraditionallyReadsBackAsTheSameKey(final int keySize, @TempDir File tempDir)
		throws Exception
	{
		DSAPrivateKey privateKey = newDsaPrivateKey(keySize);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		PrivateKeyWriter.write(privateKey, outputStream, KeyFileFormat.PEM, KeyFormat.PKCS_1);
		File file = new File(tempDir, "dsa-traditional.pem");
		Files.write(file.toPath(), outputStream.toByteArray());

		PrivateKey readBack = PrivateKeyReader.readPemPrivateKey(file);

		assertArrayEquals(privateKey.getEncoded(), readBack.getEncoded(),
			"a dsa key of " + keySize + " bits must come back off its traditional form");
	}

	/**
	 * The header stays what it was, and the body is no longer the stripped wrapper it used to be.
	 *
	 * @param keySize
	 *            the key size to generate with
	 * @throws Exception
	 *             if key generation or the conversion fails
	 */
	@ParameterizedTest
	@ValueSource(ints = { 1024, 2048 })
	void theHeaderIsUnchangedAndTheBodyIsNoLongerABareNumber(final int keySize) throws Exception
	{
		DSAPrivateKey privateKey = newDsaPrivateKey(keySize);

		PemObject pemObject = PemObjectReader
			.getPemObject(PrivateKeyExtensions.toPemFormat(privateKey));

		assertEquals(PemType.DSA_PRIVATE_KEY.getName(), pemObject.getType());
		byte[] strippedWrapper = org.bouncycastle.asn1.pkcs.PrivateKeyInfo
			.getInstance(privateKey.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded();
		assertNotEquals(strippedWrapper.length, pemObject.getContent().length,
			"the body must no longer be the stripped wrapper, which for dsa is x alone");
		assertTrue(pemObject.getContent().length > strippedWrapper.length,
			"the body must have grown by p, q, g and y");
	}
}
