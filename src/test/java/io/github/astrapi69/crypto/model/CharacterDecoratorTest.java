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
package io.github.astrapi69.crypto.model;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import org.testng.annotations.Test;

/**
 * The unit test class for the class {@link CharacterDecorator}
 */
public class CharacterDecoratorTest
{

	/**
	 * Test method for {@link CharacterDecorator} builders
	 */
	@Test
	public void testCreation()
	{
		Character actual;
		Character expected;
		CharacterDecorator decorator = CharacterDecorator.builder().prefix(Character.valueOf('$'))
			.suffix(Character.valueOf('?')).build();
		assertNotNull(decorator);

		actual = decorator.getPrefix();
		expected = '$';
		assertEquals(actual, expected);

		actual = decorator.getSuffix();
		expected = '?';
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link CharacterDecorator} builders
	 */
	@Test(expectedExceptions = { NullPointerException.class })
	public void testCreationWithNPE()
	{
		CharacterDecorator decorator = CharacterDecorator.builder().build();
		assertNotNull(decorator);
	}

}
