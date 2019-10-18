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
package de.alpharogroup.crypto.model;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import java.nio.charset.Charset;

import org.testng.annotations.Test;

/**
 * The unit test class for the class {@link ByteArrayDecorator}
 */
public class ByteArrayDecoratorTest
{

	/**
	 * Test method for {@link ByteArrayDecorator} builders
	 */
	@Test
	public void testCreation()
	{
		byte[] actual;
		byte[] expected;
		byte[] prefix;
		byte[] suffix;
		prefix = "ab".getBytes(Charset.forName("UTF-8"));
		suffix = "xy".getBytes(Charset.forName("UTF-8"));
		ByteArrayDecorator decorator = ByteArrayDecorator.builder()
			.prefix(prefix).suffix(suffix).build();
		assertNotNull(decorator);

		actual = decorator.getPrefix();
		expected = prefix;
		assertEquals(actual, expected);

		actual = decorator.getSuffix();
		expected = suffix;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link ByteArrayDecorator} builders
	 */
	@Test(expectedExceptions = { NullPointerException.class })
	public void testCreationWithNPE()
	{
		ByteArrayDecorator decorator = ByteArrayDecorator.builder().build();
		assertNotNull(decorator);
	}

}
