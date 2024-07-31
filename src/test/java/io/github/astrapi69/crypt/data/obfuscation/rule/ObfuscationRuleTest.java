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
package io.github.astrapi69.crypt.data.obfuscation.rule;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.meanbean.test.BeanTester;
import org.meanbean.test.BeanVerifier;

/**
 * The unit test class for the class {@link ObfuscationRule}
 */
public class ObfuscationRuleTest
{

	/**
	 * Test method for {@link ObfuscationRule} constructors and builders
	 */
	@Test
	public final void testConstructors()
	{
		ObfuscationRule<Character, Character> model;
		model = new ObfuscationRule<>('a', 'b');
		assertNotNull(model);
		model = ObfuscationRule.<Character, Character> builder().character('a').replaceWith('b')
			.build();
		assertNotNull(model);
	}

	/**
	 * Test method for {@link ObfuscationRule}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(ObfuscationRule.class);

		BeanVerifier.forClass(ObfuscationRule.class).editSettings().edited()
			.verifyGettersAndSetters().verifyToString().verifyEqualsAndHashCode();
	}

	/**
	 * Parameterized test method for {@link ObfuscationRule} with CSV source
	 *
	 * @param character
	 *            the character to be obfuscated
	 * @param replaceWith
	 *            the replacement character(s)
	 */
	@ParameterizedTest
	@CsvSource({ "'a', 'b'", "'x', 'y'", "'1', '2'", "'$', '%'" })
	public void testWithCsvSource(char character, char replaceWith)
	{
		ObfuscationRule<Character, Character> model = new ObfuscationRule<>(character, replaceWith);
		assertNotNull(model);
		assertEquals(character, model.getCharacter());
		assertEquals(replaceWith, model.getReplaceWith());
	}
}
