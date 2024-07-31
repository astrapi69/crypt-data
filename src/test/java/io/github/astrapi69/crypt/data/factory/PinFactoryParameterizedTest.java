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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import io.github.astrapi69.collection.list.ListFactory;

/**
 * The parameterized test class for {@link PinFactory} using CSV file input
 */
public class PinFactoryParameterizedTest
{

	/**
	 * Parameterized test method for {@link PinFactory#newPins(List, List)}
	 *
	 * @param localDatesStr
	 *            the local dates as a comma-separated string
	 * @param datePatternsStr
	 *            the date patterns as a comma-separated string
	 * @param expectedSize
	 *            the expected size of the generated pin list
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/pin_factory_test_data.csv", numLinesToSkip = 1)
	public void testNewPinsWithCsv(String localDatesStr, String datePatternsStr, int expectedSize)
	{
		List<LocalDate> localDates = Stream.of(localDatesStr.split(",")).map(LocalDate::parse)
			.collect(Collectors.toList());
		List<String> datePatterns = ListFactory.newArrayList(datePatternsStr.split(","));
		List<String> pins = PinFactory.newPins(localDates, datePatterns);
		assertEquals(pins.size(), expectedSize);
	}
}
