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

import java.security.Key;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;

import lombok.NonNull;

/**
 * The class {@link KeyExtensions} provides utility methods for key transformations and retrievals.
 */
public final class KeyExtensions
{

	private KeyExtensions()
	{
	}

	/**
	 * Transform the given encoded key as byte array to a base64 encoded {@link String} value
	 *
	 * @param encodedKey
	 *            the encoded key
	 * @return the new base64 encoded {@link String} value
	 */
	public static String toBase64(final byte[] encodedKey)
	{
		return Base64.encodeBase64String(encodedKey);
	}

	/**
	 * Transform the given encoded key as byte array to a base64 binary encoded {@link String} value
	 *
	 * @param encodedKey
	 *            the encoded key
	 * @return the new base64 binary encoded {@link String} value
	 */
	public static String toBase64Binary(final byte[] encodedKey)
	{
		return DatatypeConverter.printBase64Binary(encodedKey);
	}

	/**
	 * Transform the given base64 encoded string to an encoded key as byte array value
	 *
	 * @param base64
	 *            the base64 encoded string
	 * @return the new encoded key as byte array value
	 */
	public static byte[] decodeBase64(String base64)
	{
		return Base64.decodeBase64(base64);
	}

	/**
	 * Gets the standard algorithm name from the given {@link Key} object
	 *
	 * @param key
	 *            the {@link Key} object
	 * @return the name of the algorithm from the given {@link Key} object
	 */
	public static String getAlgorithm(@NonNull final Key key)
	{
		return key.getAlgorithm();
	}

	/**
	 * Gets the byte array from the given {@link Key} object
	 *
	 * @param key
	 *            the {@link Key} object
	 * @return the byte array from the given {@link Key} object
	 */
	public static byte[] getEncoded(@NonNull final Key key)
	{
		return key.getEncoded();
	}

	/**
	 * Gets the format from the given {@link Key} object
	 *
	 * @param key
	 *            the {@link Key} object
	 * @return the format from the given {@link Key} object
	 */
	public static String getFormat(@NonNull final Key key)
	{
		return key.getFormat();
	}
}
