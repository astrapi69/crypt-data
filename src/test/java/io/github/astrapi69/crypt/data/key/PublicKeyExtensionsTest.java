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

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.checksum.FileChecksumExtensions;
import io.github.astrapi69.crypt.api.algorithm.MdAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeySize;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link PublicKeyExtensions}
 */
public class PublicKeyExtensionsTest
{

	/** The hex string encoded for use in tests */
	public static String HEX_STRING_ENCODED = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100de9ad9316a7690eeab7c434ee29ed728d2bd3868ac26cc78286d6019f49cb337507c8c56ffa29a0045a08544a17759f6b725fa2e8dd4a80e6df4eca1c949ed5e7010d8264f63936ad9ae4709b1f67bd408cc97623c13425d3b37c08a6b20626fd93d0ef6a90e1bb088aa16638ab9e168650002a312d21bd50e7f80029cefd0570989d68ee6a5f9e8bb28e653e93960910441eac10c9b5e116b0e96d36d8d2ed0a857a200e743e8c6b7d94c12cf121af287d05b96dd3b97b03351938b874bdc3f8db6f1d430b5b2314cbf78cd1e8e13acaa29bd195c2f60f7b87a7f880008794f835de6525081118bf155910c4835125fd9b01dbd134381316d0945b8250766610203010001";

	/** The public key base64 encoded for use in tests */
	public static String PUBLIC_KEY_BASE64_ENCODED = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3prZMWp2kO6rfENO4p7X"
		+ "KNK9OGisJsx4KG1gGfScszdQfIxW/6KaAEWghUShd1n2tyX6Lo3UqA5t9OyhyUnt"
		+ "XnAQ2CZPY5Nq2a5HCbH2e9QIzJdiPBNCXTs3wIprIGJv2T0O9qkOG7CIqhZjirnh"
		+ "aGUAAqMS0hvVDn+AApzv0FcJidaO5qX56Lso5lPpOWCRBEHqwQybXhFrDpbTbY0u"
		+ "0KhXogDnQ+jGt9lMEs8SGvKH0FuW3TuXsDNRk4uHS9w/jbbx1DC1sjFMv3jNHo4T"
		+ "rKopvRlcL2D3uHp/iAAIeU+DXeZSUIERi/FVkQxINRJf2bAdvRNDgTFtCUW4JQdm" + "YQIDAQAB";

	/** The public key in pem format for use in tests */
	public static String PUBLIC_KEY_PEM_FORMATED = PublicKeyReader.BEGIN_PUBLIC_KEY_PREFIX
		+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3prZMWp2kO6rfENO4p7X" + "\n"
		+ "KNK9OGisJsx4KG1gGfScszdQfIxW/6KaAEWghUShd1n2tyX6Lo3UqA5t9OyhyUnt" + "\n"
		+ "XnAQ2CZPY5Nq2a5HCbH2e9QIzJdiPBNCXTs3wIprIGJv2T0O9qkOG7CIqhZjirnh" + "\n"
		+ "aGUAAqMS0hvVDn+AApzv0FcJidaO5qX56Lso5lPpOWCRBEHqwQybXhFrDpbTbY0u" + "\n"
		+ "0KhXogDnQ+jGt9lMEs8SGvKH0FuW3TuXsDNRk4uHS9w/jbbx1DC1sjFMv3jNHo4T" + "\n"
		+ "rKopvRlcL2D3uHp/iAAIeU+DXeZSUIERi/FVkQxINRJf2bAdvRNDgTFtCUW4JQdm" + "\n" + "YQIDAQAB"
		+ "\n" + PublicKeyReader.END_PUBLIC_KEY_SUFFIX;

	File derDir;

	File pemDir;

	File privateKeyDerFile;
	File privateKeyPemFile;
	PublicKey publicKey;
	File publicKeyPemFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privateKeyPemFile = new File(pemDir, "private.pem");
		publicKeyPemFile = new File(pemDir, "public.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");
	}

	/**
	 * Test method for {@link PublicKeyExtensions#getKeyLength(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testGetKeyLength() throws Exception
	{
		int actual;
		int expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.getKeyLength(publicKey);
		expected = 2048;
		assertEquals(expected, actual);
		// new scenario...
		actual = PublicKeyExtensions.getKeyLength(null);
		expected = -1;
		assertEquals(expected, actual);
		// new scenario...
		publicKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DSA, KeySize.KEYSIZE_1024)
			.getPublic();
		actual = PublicKeyExtensions.getKeyLength(publicKey);
		expected = 1024;
		assertEquals(expected, actual);
		// new scenario...
		publicKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.EC, KeySize.KEYSIZE_4096)
			.getPublic();
		actual = PublicKeyExtensions.getKeyLength(publicKey);
		expected = 239;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PublicKeyExtensions#toBase64(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testToBase64() throws Exception
	{
		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);
		actual = PublicKeyExtensions.toBase64(publicKey);
		expected = PUBLIC_KEY_BASE64_ENCODED;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toHexString(PrivateKey)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testToHexString() throws Exception
	{
		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.toHexString(publicKey);
		expected = HEX_STRING_ENCODED;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toHexString(PrivateKey)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testToHexStringBoolean() throws Exception
	{
		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.toHexString(publicKey, false);
		expected = HEX_STRING_ENCODED.toUpperCase();
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PublicKeyExtensions#toPemFile(PublicKey, File)}
	 */
	@Test
	public void testToPemFile() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{

		String expected;
		String actual;
		File convertedPublickeyPemFile;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);
		convertedPublickeyPemFile = new File(pemDir, "converted-public.pem");
		PublicKeyExtensions.toPemFile(publicKey, convertedPublickeyPemFile);
		expected = FileChecksumExtensions.getChecksum(publicKeyPemFile,
			MdAlgorithm.MD5.getAlgorithm());
		actual = FileChecksumExtensions.getChecksum(convertedPublickeyPemFile,
			MdAlgorithm.MD5.getAlgorithm());
		assertEquals(expected, actual);
		DeleteFileExtensions.delete(convertedPublickeyPemFile);
	}

	/**
	 * Test method for {@link PublicKeyExtensions#toBase64(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testToPemFormat() throws Exception
	{
		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.toPemFormat(publicKey);
		expected = ReadFileExtensions.fromFile(publicKeyPemFile);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link PublicKeyExtensions#getFormat(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testGetFormat() throws Exception
	{
		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.getFormat(publicKey);
		expected = "X.509";
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link PublicKeyExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PublicKeyExtensions.class);
	}

	/**
	 * Parameterized test method for {@link PublicKeyExtensions#getAlgorithm(PublicKey)}
	 *
	 * @param algorithm
	 *            the expected algorithm
	 * @param keyFile
	 *            the file containing the public key
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/public_keys.csv", numLinesToSkip = 1)
	public void testGetAlgorithmParameterized(String algorithm, String keyFile) throws Exception
	{
		File file = new File(pemDir, keyFile);
		PublicKey publicKey = PublicKeyReader.readPemPublicKey(file, algorithm);
		String actual = PublicKeyExtensions.getAlgorithm(publicKey);
		assertEquals(algorithm, actual);
	}

	/**
	 * Test method for {@link PublicKeyExtensions#getEncoded(PublicKey)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	@Test
	public void testGetEncoded() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		byte[] expected;
		byte[] actual;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.getEncoded(publicKey);
		expected = publicKey.getEncoded();
		assertArrayEquals(expected, actual);
	}

}
