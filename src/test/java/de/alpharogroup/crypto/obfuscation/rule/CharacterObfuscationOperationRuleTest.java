/**
 *
 */
package de.alpharogroup.crypto.obfuscation.rule;

import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

/**
 * The unit test class for the class {@link CharacterObfuscationOperationRule}
 */
public class CharacterObfuscationOperationRuleTest
{

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
