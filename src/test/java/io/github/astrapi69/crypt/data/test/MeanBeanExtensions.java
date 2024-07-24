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
