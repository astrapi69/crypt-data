/**
 *
 */
package de.alpharogroup.crypto.obfuscation.rule;

import static org.testng.Assert.assertEquals;

import java.util.Set;

import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.collections.set.SetFactory;

/**
 * The unit test class for the class {@link CharacterObfuscationOperationRule}
 */
public class CharacterObfuscationOperationRuleTest
{


	@Test
	public void testInverse()
	{
		Character character;
		Set<Integer> indexes;
		boolean inverted;
		Operation operation;
		Character replaceWith;
		CharacterObfuscationOperationRule rule;
		Character actual;
		Character expected;

		inverted = false;
		character = Character.valueOf('a');
		replaceWith = 'b';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0, 2);
		rule = new CharacterObfuscationOperationRule(character, indexes, inverted, null, operation,
			replaceWith);

		rule.inverse();

		actual = rule.getCharacter();
		expected = replaceWith;
		assertEquals(actual, expected);

		actual = rule.getReplaceWith();
		expected = character;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link CharacterObfuscationOperationRule}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(CharacterObfuscationOperationRule.class);
	}
}
