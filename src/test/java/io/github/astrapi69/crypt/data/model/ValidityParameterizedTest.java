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
package io.github.astrapi69.crypt.data.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.ZonedDateTime;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test class for {@link Validity} using JUnit 5 with parameterized tests. This class reads test
 * data from a CSV file and verifies the correctness of the {@link Validity#getValidityInDays()}
 * method.
 */
class ValidityParameterizedTest
{

	/**
	 * Parameterized test for {@link Validity#getValidityInDays()}. The test data is provided by the
	 * {@link #validityDataProvider()} method.
	 *
	 * @param notBefore
	 *            the start time of the validity period
	 * @param notAfter
	 *            the end time of the validity period
	 * @param expectedDays
	 *            the expected number of days between {@code notBefore} and {@code notAfter}
	 */
	@ParameterizedTest
	@MethodSource("validityDataProvider")
	void testGetValidityInDays(ZonedDateTime notBefore, ZonedDateTime notAfter, long expectedDays)
	{
		Validity validity = Validity.builder().notBefore(notBefore).notAfter(notAfter).build();
		assertEquals(expectedDays, validity.getValidityInDays());
	}

	/**
	 * Provides test data for the parameterized test
	 * {@link #testGetValidityInDays(ZonedDateTime, ZonedDateTime, long)}. The test data is read
	 * from a CSV file located at {@code src/test/resources/validity_data.csv}.
	 *
	 * @return a stream of arguments to be passed to the parameterized test
	 * @throws Exception
	 *             if an I/O error occurs reading from the CSV file
	 */
	static Stream<Arguments> validityDataProvider() throws Exception
	{
		return Files.lines(Paths.get("src/test/resources/validity_data.csv")).skip(1) // Skip header
			.map(line -> line.split(",")).map(data -> Arguments.of(ZonedDateTime.parse(data[0]),
				ZonedDateTime.parse(data[1]), Long.parseLong(data[2])));
	}
}
