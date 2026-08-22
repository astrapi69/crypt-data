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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.key.KeyFileFormat;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.crypt.data.key.reader.EncryptedPrivateKeyReader;

/**
 * Parameterized contract test for the stream based writers {@link PrivateKeyWriter},
 * {@link PublicKeyWriter}, {@link CertificateWriter} and {@link EncryptedPrivateKeyWriter}: the
 * expected bytes must be written and the given stream must be closed afterwards
 */
class KeyWriterStreamContractParameterizedTest
{

	private static final String PASSWORD = "secret";

	private static KeyPair keyPair;
	private static X509Certificate certificate;

	@TempDir
	Path tempDir;

	/**
	 * A {@link ByteArrayOutputStream} that remembers whether it was closed
	 */
	static final class TrackingOutputStream extends ByteArrayOutputStream
	{
		private boolean closed;

		@Override
		public void close() throws IOException
		{
			closed = true;
			super.close();
		}

		boolean isClosed()
		{
			return closed;
		}
	}

	/**
	 * A write operation against an {@link OutputStream}
	 */
	@FunctionalInterface
	interface WriteAction
	{
		void write(OutputStream outputStream) throws Exception;
	}

	/**
	 * A check of the bytes that were written
	 */
	@FunctionalInterface
	interface WrittenBytesCheck
	{
		void check(byte[] written) throws Exception;
	}

	/**
	 * One writer call with the check of its output
	 *
	 * @param description
	 *            the writer call
	 * @param action
	 *            the write operation
	 * @param check
	 *            the check of the written bytes
	 */
	record WriterCase(String description, WriteAction action, WrittenBytesCheck check) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		keyPair = generator.generateKeyPair();
		X500Name name = new X500Name("CN=Writer Test");
		certificate = CertFactory.newX509CertificateV3(keyPair, name, 1, name, "SHA256withRSA");
	}

	private static void assertPemCertificate(final byte[] written) throws Exception
	{
		String pem = new String(written, StandardCharsets.US_ASCII);
		assertTrue(pem.startsWith(CertificateReader.BEGIN_CERTIFICATE_PREFIX), pem);
		assertTrue(pem.endsWith(CertificateReader.END_CERTIFICATE_SUFFIX), pem);
		String body = pem.substring(CertificateReader.BEGIN_CERTIFICATE_PREFIX.length(),
			pem.length() - CertificateReader.END_CERTIFICATE_SUFFIX.length());
		assertArrayEquals(certificate.getEncoded(), Base64.getMimeDecoder().decode(body));
	}

	private static void assertEncryptedPrivateKey(final byte[] written) throws Exception
	{
		assertFalse(Arrays.equals(keyPair.getPrivate().getEncoded(), written),
			"the key must not be written in clear");
		PrivateKey decrypted = EncryptedPrivateKeyReader.readPasswordProtectedPrivateKey(written,
			PASSWORD, "RSA");
		assertArrayEquals(keyPair.getPrivate().getEncoded(), decrypted.getEncoded());
	}

	static Stream<WriterCase> writerCases()
	{
		return Stream.of(
			new WriterCase("PrivateKeyWriter.write(PrivateKey, OutputStream)",
				outputStream -> PrivateKeyWriter.write(keyPair.getPrivate(), outputStream),
				written -> assertArrayEquals(keyPair.getPrivate().getEncoded(), written)),
			new WriterCase("PublicKeyWriter.write(PublicKey, OutputStream)",
				outputStream -> PublicKeyWriter.write(keyPair.getPublic(), outputStream),
				written -> assertArrayEquals(keyPair.getPublic().getEncoded(), written)),
			new WriterCase("CertificateWriter.write(..., DER)",
				outputStream -> CertificateWriter.write(certificate, outputStream,
					KeyFileFormat.DER),
				written -> assertArrayEquals(certificate.getEncoded(), written)),
			new WriterCase("CertificateWriter.write(..., PEM)",
				outputStream -> CertificateWriter.write(certificate, outputStream,
					KeyFileFormat.PEM),
				KeyWriterStreamContractParameterizedTest::assertPemCertificate),
			new WriterCase("EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(..., stream)",
				outputStream -> EncryptedPrivateKeyWriter
					.encryptPrivateKeyWithPassword(keyPair.getPrivate(), outputStream, PASSWORD),
				KeyWriterStreamContractParameterizedTest::assertEncryptedPrivateKey));
	}

	/**
	 * Test method for the stream based writer methods
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if writing fails
	 */
	@ParameterizedTest
	@MethodSource("writerCases")
	void writerWritesExpectedBytesAndClosesStream(final WriterCase testCase) throws Exception
	{
		TrackingOutputStream outputStream = new TrackingOutputStream();

		testCase.action().write(outputStream);

		assertTrue(outputStream.size() > 0, testCase.description());
		testCase.check().check(outputStream.toByteArray());
		assertTrue(outputStream.isClosed(), testCase.description() + " must close the stream");
	}

	/**
	 * Test method for {@link PublicKeyWriter#write(java.security.PublicKey, File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@Test
	void publicKeyWriterWritesEncodedKeyToFile() throws IOException
	{
		File file = tempDir.resolve("public.der").toFile();

		PublicKeyWriter.write(keyPair.getPublic(), file);

		assertArrayEquals(keyPair.getPublic().getEncoded(), Files.readAllBytes(file.toPath()));
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyWriter#encryptPrivateKeyWithPassword(PrivateKey, String)}: a random
	 * salt is used, so two encryptions of the same key differ but both decrypt
	 *
	 * @throws Exception
	 *             if encryption fails
	 */
	@Test
	void encryptPrivateKeyWithPasswordUsesRandomSalt() throws Exception
	{
		byte[] first = EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(keyPair.getPrivate(),
			PASSWORD);
		byte[] second = EncryptedPrivateKeyWriter
			.encryptPrivateKeyWithPassword(keyPair.getPrivate(), PASSWORD);

		assertEquals(first.length, second.length);
		assertFalse(Arrays.equals(first, second), "a fresh random salt must be used each time");
		assertEncryptedPrivateKey(first);
		assertEncryptedPrivateKey(second);
	}
}
