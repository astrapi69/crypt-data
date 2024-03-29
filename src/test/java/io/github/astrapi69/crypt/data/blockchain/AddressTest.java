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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.evaluate.object.evaluator.EqualsHashCodeAndToStringEvaluator;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link Address}
 */
public class AddressTest
{

	/**
	 * Test method for {@link Address} constructors
	 */
	@Test
	public final void testConstructors() throws InvalidKeySpecException, NoSuchAlgorithmException,
		NoSuchProviderException, IOException
	{
		Address address;
		File publickeyPemDir;
		File publickeyPemFile;
		PublicKey publicKey;

		address = new Address();
		assertNotNull(address);

		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");
		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		address = new Address("foo", publicKey.getEncoded());
		assertNotNull(address);
	}

	/**
	 * Test method for {@link Address#equals(Object)} , {@link Address#hashCode()} and
	 * {@link Address#toString()}
	 */
	@Test
	@Disabled
	public void testEqualsHashcodeAndToStringWithClass()
		throws NoSuchMethodException, NoSuchFieldException, IllegalAccessException,
		InstantiationException, ClassNotFoundException, InvocationTargetException, IOException
	{
		boolean expected;
		boolean actual;


		actual = EqualsHashCodeAndToStringEvaluator
			.evaluateEqualsHashcodeAndToString(Address.class);
		expected = true;
		assertEquals(expected, actual);
	}


	/**
	 * Test method for {@link Address} with {@link BeanTester}
	 */
	@Test
	@Disabled
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(Address.class);
	}
}
