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
package io.github.astrapi69.crypt.data.key.writer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Objects;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.api.key.KeyFormat;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;

/**
 * The class {@link PrivateKeyWriter} is a utility class for write public keys in files or streams.
 */
public final class PrivateKeyWriter
{

	private PrivateKeyWriter()
	{
	}

	/**
	 * Write the given {@link PrivateKey} into the given {@link File} in the *.der format.
	 *
	 * @param privateKey
	 *            the private key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void write(final PrivateKey privateKey, final File file) throws IOException
	{
		Objects.requireNonNull(file);
		write(privateKey, new FileOutputStream(file));
	}

	/**
	 * Write the given {@link PrivateKey} into the given {@link OutputStream} in the *.der format.
	 *
	 * @param privateKey
	 *            the private key
	 * @param outputStream
	 *            the output stream to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void write(final PrivateKey privateKey, final OutputStream outputStream)
		throws IOException
	{
		Objects.requireNonNull(outputStream);
		final byte[] privateKeyBytes = privateKey.getEncoded();
		final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		outputStream.write(keySpec.getEncoded());
		outputStream.close();
	}

	/**
	 * Write the given {@link PrivateKey} into the given {@link OutputStream} in the given formats.
	 *
	 * @param privateKey
	 *            the private key
	 * @param outputStream
	 *            the output stream
	 * @param fileFormat
	 *            the file format
	 * @param keyFormat
	 *            the private key format
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void write(final PrivateKey privateKey, final OutputStream outputStream,
		final KeyFileFormat fileFormat, final KeyFormat keyFormat) throws IOException
	{
		Objects.requireNonNull(outputStream);
		final byte[] privateKeyBytes = privateKey.getEncoded();
		switch (fileFormat)
		{
			case PEM :
				if (keyFormat == null || keyFormat.equals(KeyFormat.PKCS_8))
				{
					// PKCS#8 is the encoding getEncoded returns, under the PRIVATE KEY header.
					// This used to route through toPemFormat, which is a PKCS#1 method and
					// stripped the wrapper, so asking for PKCS#8 produced PKCS#1 (issue #12).
					String pkcs8 = PrivateKeyExtensions.toPkcs8PemFormat(privateKey);
					outputStream.write(pkcs8.getBytes(StandardCharsets.US_ASCII));
					break;
				}
				else if (keyFormat.equals(KeyFormat.PKCS_1))
				{
					// toPemFormat picks the traditional header that belongs to the algorithm.
					// This used to call fromPKCS1ToPemFormat, which takes only bytes and so
					// labels every key RSA PRIVATE KEY - an EC or DSA key was written under the
					// wrong header (issue #12).
					String traditional = PrivateKeyExtensions.toPemFormat(privateKey);
					outputStream.write(traditional.getBytes(StandardCharsets.US_ASCII));
					break;
				}
			default : // DER is default
				final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
				outputStream.write(keySpec.getEncoded());
				break;
		}
		outputStream.close();
	}

	/**
	 * Write the given {@link PrivateKey} into the given {@link File}.
	 *
	 * @param privateKey
	 *            the private key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void writeInPemFormat(final PrivateKey privateKey, final File file)
		throws IOException
	{
		Objects.requireNonNull(file);
		KeyWriter.writeInPemFormat(privateKey, file);
	}

}
