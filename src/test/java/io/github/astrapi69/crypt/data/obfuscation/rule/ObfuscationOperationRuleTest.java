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

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.collection.set.SetFactory;
import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;
import io.github.astrapi69.evaluate.object.evaluator.EqualsHashCodeAndToStringEvaluator;

/**
 * The unit test class for the class {@link ObfuscationOperationRule}
 */
public class ObfuscationOperationRuleTest
{

	private ObfuscationOperationRule<Character, String> rule;

	@BeforeEach
	public void setUp()
	{
		rule = ObfuscationOperationRule.<Character, String> builder().character('a')
			.replaceWith("bc").operation(Operation.UPPERCASE).indexes(SetFactory.newHashSet(0, 2))
			.build();
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#getCharacter()}
	 */
	@Test
	public void testGetCharacter()
	{
		assertEquals(Character.valueOf('a'), rule.getCharacter());
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#getReplaceWith()}
	 */
	@Test
	public void testGetReplaceWith()
	{
		assertEquals("bc", rule.getReplaceWith());
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#getOperation()}
	 */
	@Test
	public void testGetOperation()
	{
		assertEquals(Operation.UPPERCASE, rule.getOperation());
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#getIndexes()}
	 */
	@Test
	public void testGetIndexes()
	{
		Set<Integer> expectedIndexes = SetFactory.newHashSet(0, 2);
		assertEquals(expectedIndexes, rule.getIndexes());
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#equals(Object)} and
	 * {@link ObfuscationOperationRule#hashCode()}
	 */
	@Test
	public void testEqualsHashCodeAndToString()
	{
		EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(rule);
	}

	/**
	 * Test method for {@link ObfuscationOperationRule} using BeanTester
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(ObfuscationOperationRule.class);
	}

	/**
	 * Test method for {@link ObfuscationOperationRule#toString()}
	 */
	@Test
	public void testToString()
	{
		String expectedToString = "ObfuscationOperationRule(character=a, indexes=[0, 2], inverted=false, operatedCharacter=Optional.empty, operation=UPPERCASE, replaceWith=bc)";
		assertEquals(expectedToString, rule.toString());
	}

	/**
	 * Parameterized test method for {@link ObfuscationOperationRule} using CSV file
	 *
	 * @param character
	 *            the character to be obfuscated
	 * @param replaceWith
	 *            the characters to replace with
	 * @param operation
	 *            the operation to be applied
	 * @param indexes
	 *            the set of indexes to apply the obfuscation
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/obfuscation_operation_rule_test_data.csv", numLinesToSkip = 1)
	public void testWithParameterizedCSV(Character character, String replaceWith,
		Operation operation, String indexes)
	{
		Set<Integer> indexSet = SetFactory.newHashSet();
		for (String index : indexes.split(","))
		{
			indexSet.add(Integer.parseInt(index.trim()));
		}
		ObfuscationOperationRule<Character, String> parameterizedRule = ObfuscationOperationRule
			.<Character, String> builder().character(character).replaceWith(replaceWith)
			.operation(operation).indexes(indexSet).build();

		assertNotNull(parameterizedRule);
		assertEquals(character, parameterizedRule.getCharacter());
		assertEquals(replaceWith, parameterizedRule.getReplaceWith());
		assertEquals(operation, parameterizedRule.getOperation());
		assertEquals(indexSet, parameterizedRule.getIndexes());
	}
}
