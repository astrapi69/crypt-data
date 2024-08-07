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

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;

import io.github.astrapi69.crypt.data.hex.HexExtensions;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.crypt.data.key.writer.PublicKeyWriter;
import io.github.astrapi69.string.StringExtensions;

/**
 * The class {@link PublicKeyExtensions}
 */
public final class PublicKeyExtensions
{

	private PublicKeyExtensions()
	{
	}

	/**
	 * Get the standard algorithm name from the given {@link PublicKey}
	 *
	 * @param publicKey
	 *            the public key
	 * @return the standard algorithm name from the given {@link PublicKey}
	 */
	public static String getAlgorithm(final PublicKey publicKey)
	{
		return publicKey.getAlgorithm();
	}

	/**
	 * Get the name of the primary encoding format from the given {@link PublicKey} or null if it
	 * does not support encoding
	 *
	 * @param publicKey
	 *            the public key
	 * @return the name of the primary encoding format from the given {@link PublicKey} or null if
	 *         it does not support encoding
	 */
	public static String getFormat(final PublicKey publicKey)
	{
		return publicKey.getFormat();
	}

	/**
	 * Get the {@link PublicKey} in its primary encoding format, or null if this key does not
	 * support encoding
	 *
	 * @param publicKey
	 *            the public key
	 * @return the {@link PublicKey} in its primary encoding format, or null if this key does not
	 *         support encoding
	 */
	public static byte[] getEncoded(final PublicKey publicKey)
	{
		return publicKey.getEncoded();
	}

	/**
	 * Gets the key length of the given {@link PublicKey}
	 *
	 * @param publicKey
	 *            the public key
	 * @return the key length
	 */
	public static int getKeyLength(final PublicKey publicKey)
	{
		int length = -1;
		if (publicKey == null)
		{
			return length;
		}
		if (publicKey instanceof RSAPublicKey)
		{
			length = ((RSAPublicKey)publicKey).getModulus().bitLength();
		}
		if (publicKey instanceof DSAPublicKey)
		{
			length = ((DSAPublicKey)publicKey).getParams().getP().bitLength();
		}
		if (publicKey instanceof ECPublicKey)
		{
			length = ((ECPublicKey)publicKey).getParams().getCurve().getField().getFieldSize();
		}

		return length;
	}

	/**
	 * Transform the given {@link PublicKey} to a base64 encoded {@link String} value
	 *
	 * @param publicKey
	 *            the public key
	 * @return the base64 encoded {@link String} value
	 */
	public static String toBase64(final PublicKey publicKey)
	{
		return KeyExtensions.toBase64(publicKey.getEncoded());
	}

	/**
	 * Transform the given {@link PublicKey} to a hexadecimal {@link String} value
	 *
	 * @param publicKey
	 *            the public key
	 * @return the new hexadecimal {@link String} value
	 */
	public static String toHexString(final PublicKey publicKey)
	{
		return toHexString(publicKey, true);
	}

	/**
	 * Transform the given {@link PublicKey} to a hexadecimal {@link String} value
	 *
	 * @param publicKey
	 *            the public key
	 * @param lowerCase
	 *            the flag if the result shall be transformed to lower case. If true the result is
	 *            in lower case
	 * @return the new hexadecimal {@link String} value
	 */
	public static String toHexString(final PublicKey publicKey, final boolean lowerCase)
	{
		return HexExtensions.toHexString(publicKey.getEncoded(), lowerCase);
	}

	/**
	 * Write the given {@link PublicKey} into the given {@link File}
	 *
	 * @param publicKey
	 *            the public key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static void toPemFile(final PublicKey publicKey, final File file) throws IOException
	{
		Objects.requireNonNull(publicKey);
		Objects.requireNonNull(file);
		PublicKeyWriter.writeInPemFormat(publicKey, file);
	}

	/**
	 * Transform the public key to pem format
	 *
	 * @param publicKey
	 *            the public key
	 * @return the public key in pem format
	 */
	public static String toPemFormat(final PublicKey publicKey)
	{
		final String publicKeyAsBase64String = toBase64(publicKey);
		final List<String> parts = StringExtensions.splitByFixedLength(publicKeyAsBase64String, 64);

		final StringBuilder sb = new StringBuilder();
		sb.append(PublicKeyReader.BEGIN_PUBLIC_KEY_PREFIX);
		for (final String part : parts)
		{
			sb.append(part);
			sb.append(System.lineSeparator());
		}
		sb.append(PublicKeyReader.END_PUBLIC_KEY_SUFFIX);
		sb.append(System.lineSeparator());
		return sb.toString();
	}
}
