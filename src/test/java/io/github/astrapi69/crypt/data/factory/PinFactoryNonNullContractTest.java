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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for {@link PinFactory#newPins(List, List)} and its non-null contract
 */
class PinFactoryNonNullContractTest
{

	/**
	 * One pin generation
	 *
	 * @param localDates
	 *            the dates
	 * @param datePatterns
	 *            the patterns
	 * @param expected
	 *            the expected, naturally sorted pins
	 */
	record PinCase(List<LocalDate> localDates, List<String> datePatterns, List<String> expected) {
	}

	/**
	 * One call with a null argument
	 *
	 * @param description
	 *            what is passed as null
	 * @param call
	 *            the call
	 */
	record NullArgumentCase(String description, Executable call) {
	}

	static Stream<PinCase> pinCases()
	{
		return Stream.of(
			new PinCase(List.of(LocalDate.of(2020, 1, 2)), List.of("ddMM", "MMdd"),
				List.of("0102", "0201")),
			new PinCase(List.of(LocalDate.of(2020, 12, 31), LocalDate.of(2021, 1, 1)),
				List.of("ddMMyyyy"), List.of("01012021", "31122020")),
			new PinCase(List.of(LocalDate.of(2020, 12, 31), LocalDate.of(2021, 1, 1)),
				List.of("yyyy", "MM"), List.of("01", "12", "2020", "2021")),
			new PinCase(List.of(), List.of("ddMM"), List.of()),
			new PinCase(List.of(LocalDate.of(2020, 1, 2)), List.of(), List.of()));
	}

	/**
	 * Test method for {@link PinFactory#newPins(List, List)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("pinCases")
	void newPins(final PinCase testCase)
	{
		assertEquals(testCase.expected(),
			PinFactory.newPins(testCase.localDates(), testCase.datePatterns()));
	}

	static Stream<NullArgumentCase> nullArgumentCases()
	{
		return Stream.of(
			new NullArgumentCase("dates", () -> PinFactory.newPins(null, List.of("ddMM"))),
			new NullArgumentCase("patterns",
				() -> PinFactory.newPins(List.of(LocalDate.of(2020, 1, 2)), null)));
	}

	/**
	 * Test method for the non-null contract of {@link PinFactory#newPins(List, List)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("nullArgumentCases")
	void nonNullContract(final NullArgumentCase testCase)
	{
		assertThrows(NullPointerException.class, testCase.call(), testCase.description());
	}
}
