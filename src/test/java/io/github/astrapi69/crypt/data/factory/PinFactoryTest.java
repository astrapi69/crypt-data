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
package io.github.astrapi69.crypt.data.factory;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.LocalDate;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.collection.list.ListFactory;

/**
 * The unit test class for {@link PinFactory}
 */
public class PinFactoryTest
{

	/**
	 * Test method for {@link PinFactory#newPins(List, List)}
	 */
	@Test
	public void testNewPins()
	{
		List<LocalDate> localDates;
		List<String> datePatterns;
		List<String> pins;

		datePatterns = ListFactory.newArrayList("ddMM", "MMdd", "MMyy", "yyyy");
		localDates = ListFactory.newArrayList(LocalDate.of(1963, 11, 14), LocalDate.of(1967, 4, 18),
			LocalDate.of(1977, 5, 21), LocalDate.of(1981, 1, 19), LocalDate.of(1988, 3, 11));
		pins = PinFactory.newPins(localDates, datePatterns);
		assertEquals(pins.size(), 20);
		// pins.stream().forEach(System.out::println);

		datePatterns = ListFactory.newArrayList("ddMMyy", "MMddyy", "MMyydd", "yyyydd");
		localDates = ListFactory.newArrayList(LocalDate.of(1963, 11, 14), LocalDate.of(1967, 4, 18),
			LocalDate.of(1977, 5, 21), LocalDate.of(1981, 1, 19), LocalDate.of(1988, 3, 11));
		pins = PinFactory.newPins(localDates, datePatterns);
		assertEquals(pins.size(), 20);
		// pins.stream().forEach(System.out::println);
	}

	/**
	 * Additional test method for edge cases and additional coverage for
	 * {@link PinFactory#newPins(List, List)}
	 */
	@Test
	public void testNewPinsWithAdditionalDates()
	{
		List<LocalDate> localDates = ListFactory.newArrayList(LocalDate.of(2000, 2, 29),
			LocalDate.of(2024, 7, 4));
		List<String> datePatterns = ListFactory.newArrayList("dd-MM-yyyy", "yyyy/MM/dd");
		List<String> pins = PinFactory.newPins(localDates, datePatterns);
		assertEquals(pins.size(), 4);
		// pins.stream().forEach(System.out::println);
	}

	/**
	 * Test method for {@link PinFactory} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PinFactory.class);
	}
}
