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
package io.github.astrapi69.crypto.key.writer;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.delete.DeleteFileExtensions;
import io.github.astrapi69.search.PathFinder;
import io.github.astrapi69.checksum.FileChecksumExtensions;
import io.github.astrapi69.crypto.algorithm.MdAlgorithm;
import io.github.astrapi69.crypto.key.PrivateKeyExtensions;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypto.key.reader.PublicKeyReader;

/**
 * The unit test class for the class {@link PublicKeyWriter}
 */
public class PublicKeyWriterTest
{

	File derDir;
	File pemDir;

	PrivateKey privateKey;

	File privateKeyPemFile;
	PublicKey publicKey;
	File publicKeyDerFile;

	File publicKeyPemFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publicKeyPemFile = new File(pemDir, "public.pem");
		privateKeyPemFile = new File(pemDir, "private.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publicKeyDerFile = new File(derDir, "public.der");
	}

	/**
	 * Test method for {@link PublicKeyWriter} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PublicKeyWriter.class);
	}

	/**
	 * Test method for {@link PublicKeyWriter#write(PublicKey, File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testWriteFile() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		Checksum expected;
		Checksum actual;
		File writtenPublickeyDerFile;
		// new scenario...
		publicKey = PublicKeyReader.readPublicKey(publicKeyDerFile);
		writtenPublickeyDerFile = new File(derDir, "written-public.der");
		PublicKeyWriter.write(publicKey, writtenPublickeyDerFile);
		Checksum checksum = new CRC32();
		expected = FileUtils.checksum(publicKeyDerFile, checksum);
		actual = FileUtils.checksum(writtenPublickeyDerFile, checksum);
		assertEquals(expected.getValue(), actual.getValue());
		DeleteFileExtensions.delete(writtenPublickeyDerFile);
	}

	/**
	 * Test method for {@link PublicKeyWriter#writeInPemFormat(PublicKey, File)}
	 *
	 * @throws Exception
	 *             is thrown if a security issue occurs
	 */
	@Test
	public void testWriteInPemFormat() throws Exception
	{
		String expected;
		String actual;
		File convertedPublickeyPemFile;
		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);
		convertedPublickeyPemFile = new File(pemDir, "converted-public.pem");
		PublicKeyWriter.writeInPemFormat(publicKey, convertedPublickeyPemFile);
		expected = FileChecksumExtensions.getChecksum(publicKeyPemFile, MdAlgorithm.MD5);
		actual = FileChecksumExtensions.getChecksum(convertedPublickeyPemFile, MdAlgorithm.MD5);
		assertEquals(expected, actual);
		DeleteFileExtensions.delete(convertedPublickeyPemFile);
	}

}
