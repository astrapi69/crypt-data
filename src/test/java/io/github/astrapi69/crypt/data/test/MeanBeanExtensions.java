package io.github.astrapi69.test;

import org.meanbean.test.BeanTester;
import org.meanbean.test.EqualsMethodTester;
import org.meanbean.test.HashCodeMethodTester;

/**
 * The type MeanBeanExtensions. This class provides utility methods to test beans using
 * {@link BeanTester}, {@link HashCodeMethodTester}, and {@link EqualsMethodTester}.
 */
public final class MeanBeanExtensions
{
	private static final BeanTester beanTester = new BeanTester();
	private static final HashCodeMethodTester hashCodeMethodTester = new HashCodeMethodTester();
	private static final EqualsMethodTester equalsMethodTester = new EqualsMethodTester();

	/**
	 * Tests the given bean class with the {@link BeanTester}, {@link HashCodeMethodTester}, and
	 * {@link EqualsMethodTester}.
	 *
	 * @param beanClass
	 *            The class type to be tested
	 */
	public static void testWithBeanTester(Class<?> beanClass)
	{
		beanTester.testBean(beanClass);
	}

	/**
	 * Tests the given bean class with the {@link HashCodeMethodTester}.
	 *
	 * @param beanClass
	 *            The class type to be tested
	 */
	public static void testWithHashCodeMethodTester(Class<?> beanClass)
	{
		hashCodeMethodTester.testHashCodeMethod(beanClass);
	}

	/**
	 * Tests the given bean class with the {@link EqualsMethodTester}.
	 *
	 * @param beanClass
	 *            The class type to be tested
	 * @param insignificantEqualsProperties
	 *            The names of properties that are not used when deciding whether objects are
	 *            logically equivalent, e.g., "lastName"
	 */
	public static void testWithEqualsMethodTester(Class<?> beanClass,
		String... insignificantEqualsProperties)
	{
		equalsMethodTester.testEqualsMethod(beanClass, insignificantEqualsProperties);
	}

	/**
	 * Tests the given bean class with the {@link BeanTester}, {@link HashCodeMethodTester}, and
	 * {@link EqualsMethodTester}
	 *
	 *
	 * @param beanClass
	 *            The class type to be tested
	 * @param insignificantEqualsProperties
	 *            The names of properties that are not used when deciding whether objects are
	 *            logically equivalent, e.g., "lastName"
	 */
	public static void testWithAllTester(Class<?> beanClass,
		String... insignificantEqualsProperties)
	{
		testWithBeanTester(beanClass);
		testWithHashCodeMethodTester(beanClass);
		testWithEqualsMethodTester(beanClass, insignificantEqualsProperties);
	}
}
