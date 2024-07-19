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
package io.github.astrapi69.crypt.data.blockchain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.data.hash.HashExtensions;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.evaluate.object.evaluator.EqualsHashCodeAndToStringEvaluator;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link Address}
 */
public class AddressTest
{

	private File publickeyPemFile;
	private PublicKey publicKey;

	@BeforeEach
	public void setUp() throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
		InvalidKeySpecException
	{
		File publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");
		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);
	}

	/**
	 * Test method for {@link Address} constructors
	 */
	@Test
	public void testConstructors() throws InvalidKeySpecException, NoSuchAlgorithmException,
		NoSuchProviderException, IOException
	{
		Address address = new Address();
		assertNotNull(address);
		assertNull(address.getName());
		assertNull(address.getPublicKey());
		assertNull(address.getHash());

		address = new Address("foo", publicKey.getEncoded());
		assertNotNull(address);
		assertEquals("foo", address.getName());
		assertArrayEquals(publicKey.getEncoded(), address.getPublicKey());
		assertNotNull(address.getHash());
	}

	/**
	 * Test method for getters and setters of class {@link Address}
	 */
	@Test
	public void testGettersAndSetters()
	{
		Address address = new Address();
		address.setName("foo");
		address.setPublicKey(publicKey.getEncoded());
		byte[] hash = new byte[] { 1, 2, 3, 4 };
		address.setHash(hash);

		assertEquals("foo", address.getName());
		assertArrayEquals(publicKey.getEncoded(), address.getPublicKey());
		assertArrayEquals(hash, address.getHash());
	}

	/**
	 * Test method for {@link Address#equals(Object)} , {@link Address#hashCode()} and
	 * {@link Address#toString()}
	 */
	@Test
	public void testEqualsHashcodeAndToStringWithClass()
	{
		boolean expected = true;
		boolean actual = EqualsHashCodeAndToStringEvaluator
			.evaluateEqualsHashcodeAndToString(Address.class);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link Address} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(Address.class);
	}

	/**
	 * Test method for {@link Address} equality
	 */
	@Test
	public void testEquality()
	{
		Address address1 = new Address("foo", publicKey.getEncoded());
		Address address2 = new Address("foo", publicKey.getEncoded());
		Address address3 = new Address("bar", publicKey.getEncoded());

		assertEquals(address1, address2);
		assertNotEquals(address1, address3);
		assertNotEquals(address2, address3);
	}

	/**
	 * Test method for {@link Address#hashCode()}
	 */
	@Test
	public void testHashCode()
	{
		Address address1 = new Address("foo", publicKey.getEncoded());
		Address address2 = new Address("foo", publicKey.getEncoded());
		Address address3 = new Address("bar", publicKey.getEncoded());

		assertEquals(address1.hashCode(), address2.hashCode());
		assertNotEquals(address1.hashCode(), address3.hashCode());
		assertNotEquals(address2.hashCode(), address3.hashCode());
	}

	/**
	 * Test method for {@link Address#canEqual(Object)}
	 */
	@Test
	public void testCanEqual()
	{
		Address address1 = new Address("foo", publicKey.getEncoded());
		Address address2 = new Address("foo", publicKey.getEncoded());
		String someString = "not an address";

		assertNotNull(address1);
		assertNotNull(address2);
		assertEquals(address1, address2);
		assertEquals(address2, address1);

		assertNotEquals(address1, someString);
		assertNotEquals(address2, someString);
	}

	/**
	 * Test method for Hash Calculation in {@link Address}
	 */
	@Test
	public void testHashCalculation()
	{
		String name = "foo";
		byte[] publicKeyBytes = publicKey.getEncoded();
		byte[] expectedHash = HashExtensions.hash(name.getBytes(), publicKeyBytes,
			HashAlgorithm.SHA256);

		Address address = new Address(name, publicKeyBytes);
		assertArrayEquals(expectedHash, address.getHash());
	}

	private void assertArrayEquals(byte[] expected, byte[] actual)
	{
		assertEquals(Arrays.toString(expected), Arrays.toString(actual));
	}
}
