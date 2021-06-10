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
package io.github.astrapi69.crypto.factories;

import static org.testng.Assert.assertEquals;

import java.time.LocalDate;
import java.util.List;

import org.testng.annotations.Test;

import de.alpharogroup.collections.list.ListFactory;

public class PinFactoryTest
{

	@Test
	public void testNewPins(){
		List<LocalDate> localDates;
		List<String> datePatterns;
		datePatterns = ListFactory.newArrayList(
			"ddMM",
			"MMdd",
			"MMyy",
			"yyyy"
		);
		localDates = ListFactory.newArrayList(
			LocalDate.of(1963, 11, 14),
			LocalDate.of(1967, 4, 18),
			LocalDate.of(1977, 5, 21),
			LocalDate.of(1981, 1, 19),
			LocalDate.of(1988, 3, 11)
		);
		List<String> pins = PinFactory.newPins(localDates, datePatterns);
		assertEquals(pins.size(), 20);
//		pins.stream().forEach(System.out::println);
	}
}
