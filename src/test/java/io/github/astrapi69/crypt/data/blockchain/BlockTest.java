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
import java.security.PublicKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.evaluate.object.evaluator.EqualsHashCodeAndToStringEvaluator;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link Block}
 */
public class BlockTest
{
	private final static byte[] fixedSignature = new byte[] { 48, 44, 2, 20, 89, 48, -114, -49, 36,
			65, 116, -5, 88, 6, -38, -110, -30, -73, 59, -53, 19, -49, 122, 90, 2, 20, 111, 38, 55,
			-120, -125, 17, -66, -8, -121, 85, 31, -82, -80, -31, -33, 116, 121, -90, 123, -113 };

	Address address;

	@BeforeEach
	public void setUp() throws Exception
	{

		File publickeyPemDir;
		File publickeyPemFile;
		PublicKey publicKey;

		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");
		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		address = new Address("foo", publicKey.getEncoded());
	}

	/**
	 * Test method for {@link Block} constructors
	 */
	@Test
	public final void testConstructors()
	{
		Block block;
		Transaction transaction;
		String text;

		block = new Block();
		assertNotNull(block);
		block.setHash(new byte[] { });

		text = "transaction-name";
		transaction = new Transaction(text, address.getHash(), fixedSignature);

		block = new Block(null, ListFactory.newArrayList(transaction), 4847556);
		assertNotNull(block);
	}

	/**
	 * Test method for {@link Block#equals(Object)} , {@link Block#hashCode()} and
	 * {@link Block#toString()}
	 */
	@Test
	@Disabled
	public void testEqualsHashcodeAndToStringWithClass()
		throws NoSuchMethodException, NoSuchFieldException, IllegalAccessException,
		InstantiationException, ClassNotFoundException, InvocationTargetException, IOException
	{
		boolean expected;
		boolean actual;

		actual = EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(Block.class);
		expected = true;
		assertEquals(expected, actual);
	}


	/**
	 * Test method for {@link Block} with {@link BeanTester}
	 */
	@Test
	@Disabled
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(Block.class);
	}
}
