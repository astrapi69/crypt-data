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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.collection.set.SetFactory;
import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;

/**
 * The unit test class for the class {@link CharacterObfuscationOperationRule}
 */
public class CharacterObfuscationOperationRuleTest
{

	/**
	 * Test method for {@link CharacterObfuscationOperationRule} using BeanTester
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(CharacterObfuscationOperationRule.class);
	}

	/**
	 * Test method for {@link CharacterObfuscationOperationRule#equals(Object)},
	 * {@link CharacterObfuscationOperationRule#hashCode()}, and
	 * {@link CharacterObfuscationOperationRule#toString()}
	 */
	@Test
	public void testEqualsHashCodeAndToString()
	{
		CharacterObfuscationOperationRule rule1 = new CharacterObfuscationOperationRule('a',
			SetFactory.newHashSet(0, 1), false, Optional.empty(), Operation.UPPERCASE, 'A');
		CharacterObfuscationOperationRule rule2 = new CharacterObfuscationOperationRule('a',
			SetFactory.newHashSet(0, 1), false, Optional.empty(), Operation.UPPERCASE, 'A');

		assertTrue(rule1.equals(rule2));
		assertEquals(rule1.hashCode(), rule2.hashCode());
		assertEquals(
			"CharacterObfuscationOperationRule(super=ObfuscationOperationRule(character=a, indexes=[0, 1], inverted=false, operatedCharacter=Optional[A], operation=UPPERCASE, replaceWith=A))",
			rule1.toString());
	}
}
