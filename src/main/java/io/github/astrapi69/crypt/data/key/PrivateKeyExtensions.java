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

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import io.github.astrapi69.crypt.api.algorithm.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.api.key.PemType;
import io.github.astrapi69.crypt.data.hex.HexExtensions;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;

/**
 * The class {@link PrivateKeyExtensions}.
 */
public final class PrivateKeyExtensions
{

	private PrivateKeyExtensions()
	{
		throw new UnsupportedOperationException(
			"This is a utility class and cannot be instantiated");
	}


	/**
	 * Transform the given byte array(of private key in PKCS#1 format) to a PEM formatted
	 * {@link String}.
	 *
	 * @param privateKeyPKCS1Formatted
	 *            the byte array(of private key in PKCS#1 format)
	 * @return the String in PEM-Format
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static String fromPKCS1ToPemFormat(final byte[] privateKeyPKCS1Formatted)
		throws IOException
	{
		PemObject pemObject = new PemObject(PemType.RSA_PRIVATE_KEY.getName(),
			privateKeyPKCS1Formatted);
		StringWriter stringWriter = new StringWriter();
		PemWriter pemWriter = new PemWriter(stringWriter);
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		String string = stringWriter.toString();
		return string;
	}

	/**
	 * Generate the corresponding {@link PublicKey} object from the given {@link PrivateKey} object.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the corresponding {@link PublicKey} object or null if generation failed.
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws InvalidKeySpecException
	 *             the invalid key spec exception
	 */
	public static PublicKey generatePublicKey(final PrivateKey privateKey)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		if (privateKey instanceof RSAPrivateKey)
		{
			final RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privateKey;
			final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privk.getModulus(),
				privk.getPublicExponent());

			final KeyFactory keyFactory = KeyFactory
				.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
			final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			return publicKey;
		}
		return null;
	}

	/**
	 * Gets the key length of the given {@link PrivateKey}.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the key length
	 */
	public static int getKeyLength(final PrivateKey privateKey)
	{
		int length = -1;
		if (privateKey == null)
		{
			return length;
		}
		if (privateKey instanceof RSAPrivateKey)
		{
			length = ((RSAPrivateKey)privateKey).getModulus().bitLength();
		}
		if (privateKey instanceof DSAPrivateKey)
		{
			length = ((DSAPrivateKey)privateKey).getParams().getQ().bitLength();
		}
		if (privateKey instanceof ECPrivateKey)
		{
			length = ((ECPrivateKey)privateKey).getParams().getCurve().getField().getFieldSize();
		}
		return length;
	}

	/**
	 * Gets the {@link KeySize} of the given {@link PrivateKey} or null if not found.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link KeySize} of the given {@link PrivateKey} or null if not found.
	 */
	public static KeySize getKeySize(final PrivateKey privateKey)
	{
		int length = getKeyLength(privateKey);
		if (length == 1024)
		{
			return KeySize.KEYSIZE_1024;
		}
		if (length == 2048)
		{
			return KeySize.KEYSIZE_2048;
		}
		if (length == 4096)
		{
			return KeySize.KEYSIZE_4096;
		}
		if (length == 8192)
		{
			return KeySize.KEYSIZE_8192;
		}
		return null;
	}

	/**
	 * Transform the given {@link PrivateKey} to a base64 encoded {@link String} value.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new base64 encoded {@link String} value.
	 */
	public static String toBase64(final PrivateKey privateKey)
	{
		return KeyExtensions.toBase64(privateKey.getEncoded());
	}

	/**
	 * Transform the given {@link PrivateKey} to a base64 encoded {@link String} value.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new base64 encoded {@link String} value.
	 */
	public static String toBase64Binary(final PrivateKey privateKey)
	{
		return KeyExtensions.toBase64Binary(privateKey.getEncoded());
	}

	/**
	 * Transform the given {@link PrivateKey} to a hexadecimal {@link String} value.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new hexadecimal {@link String} value.
	 */
	public static String toHexString(final PrivateKey privateKey)
	{
		return toHexString(privateKey, true);
	}

	/**
	 * Transform the given {@link PrivateKey} to a hexadecimal {@link String} value.
	 *
	 * @param privateKey
	 *            the private key
	 * @param lowerCase
	 *            the flag if the result shell be transform in lower case. If true the result is
	 * @return the new hexadecimal {@link String} value.
	 */
	public static String toHexString(final PrivateKey privateKey, final boolean lowerCase)
	{
		return HexExtensions.toHexString(privateKey.getEncoded(), lowerCase);
	}

	/**
	 * Transform the given private key that is in PKCS1 format and returns a {@link String} object
	 * in pem format.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link String} object in pem format generated from the given private key.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String toPemFormat(final PrivateKey privateKey) throws IOException
	{
		if (privateKey instanceof ECPrivateKey)
		{
			return PemObjectReader.toPemFormat(
				new PemObject(PemType.EC_PRIVATE_KEY.getName(), toPKCS1Format(privateKey)));
		}
		if (privateKey instanceof DSAPrivateKey)
		{
			return PemObjectReader.toPemFormat(
				new PemObject(PemType.DSA_PRIVATE_KEY.getName(), toPKCS1Format(privateKey)));
		}
		return PemObjectReader.toPemFormat(
			new PemObject(PemType.RSA_PRIVATE_KEY.getName(), toPKCS1Format(privateKey)));
	}

	/**
	 * Transform the given private key to PKCS#1 format and returns it as an byte array
	 *
	 * @param privateKey
	 *            the private key
	 * @return the byte array formatted in PKCS#1
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static byte[] toPKCS1Format(final PrivateKey privateKey) throws IOException
	{
		final byte[] encoded = privateKey.getEncoded();
		final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encoded);
		final ASN1Encodable asn1Encodable = privateKeyInfo.parsePrivateKey();
		final ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
		final byte[] privateKeyPKCS1Formatted = asn1Primitive.getEncoded();
		return privateKeyPKCS1Formatted;
	}

	/**
	 * Get the standard algorithm name from the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            the private key
	 * @return the standard algorithm name from the given {@link PrivateKey}
	 */
	public static String getAlgorithm(final PrivateKey privateKey)
	{
		return privateKey.getAlgorithm();
	}

	/**
	 * Get the name of the primary encoding format from the given {@link PrivateKey} or null it does
	 * not support encoding
	 *
	 * @param privateKey
	 *            the private key
	 * @return the name of the primary encoding format from the given {@link PrivateKey} or null it
	 *         does not support encoding
	 */
	public static String getFormat(final PrivateKey privateKey)
	{
		return privateKey.getFormat();
	}

	/**
	 * Get the {@link PrivateKey} in its primary encoding format, or null if this key does not
	 * support encoding
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link PrivateKey} in its primary encoding format, or null if this key does not *
	 *         support encoding
	 */
	public static byte[] getEncoded(final PrivateKey privateKey)
	{
		return privateKey.getEncoded();
	}


}
