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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.apache.commons.codec.binary.Base64;

import io.github.astrapi69.crypto.key.KeyFileFormat;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;

/**
 * The class {@link CertificateWriter} is a utility class for write certificates in files or streams
 * in several file formats.
 */
public final class CertificateWriter
{

	private CertificateWriter()
	{
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link File} in the given
	 * {@link KeyFileFormat} format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param file
	 *            the file to write in
	 * @param fileFormat
	 *            the file format to write
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void write(final X509Certificate certificate, final File file,
		KeyFileFormat fileFormat) throws IOException, CertificateEncodingException
	{
		Objects.requireNonNull(file);
		write(certificate, new FileOutputStream(file), fileFormat);
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link OutputStream} in the given
	 * {@link KeyFileFormat} format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param outputStream
	 *            the output stream
	 * @param fileFormat
	 *            the file format to write
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void write(final X509Certificate certificate, final OutputStream outputStream,
		KeyFileFormat fileFormat) throws IOException, CertificateEncodingException
	{
		Objects.requireNonNull(outputStream);
		final byte[] certificateBytes = certificate.getEncoded();
		switch (fileFormat)
		{
			case PEM :
				outputStream.write(
					CertificateReader.BEGIN_CERTIFICATE_PREFIX.getBytes(StandardCharsets.US_ASCII));
				outputStream.write(Base64.encodeBase64(certificateBytes, true));
				outputStream.write(
					CertificateReader.END_CERTIFICATE_SUFFIX.getBytes(StandardCharsets.US_ASCII));
				break;
			default :
				outputStream.write(certificateBytes);
				break;
		}
		outputStream.close();
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link File} in the *.der format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void writeInDerFormat(final X509Certificate certificate, final File file)
		throws IOException, CertificateEncodingException
	{
		Objects.requireNonNull(file);
		writeInDerFormat(certificate, new FileOutputStream(file));
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link OutputStream} in the *.pem
	 * format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param outputStream
	 *            the output stream to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void writeInDerFormat(final X509Certificate certificate,
		final OutputStream outputStream) throws IOException, CertificateEncodingException
	{
		Objects.requireNonNull(outputStream);
		write(certificate, outputStream, KeyFileFormat.DER);
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link File} in the *.pem format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void writeInPemFormat(final X509Certificate certificate, final File file)
		throws IOException, CertificateEncodingException
	{
		Objects.requireNonNull(file);
		writeInPemFormat(certificate, new FileOutputStream(file));
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link OutputStream} in the *.pem
	 * format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param outputStream
	 *            the output stream to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void writeInPemFormat(final X509Certificate certificate,
		final OutputStream outputStream) throws IOException, CertificateEncodingException
	{
		Objects.requireNonNull(outputStream);
		write(certificate, outputStream, KeyFileFormat.PEM);
	}

}
