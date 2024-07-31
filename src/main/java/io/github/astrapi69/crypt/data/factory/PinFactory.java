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

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

import io.github.astrapi69.collection.list.ListFactory;
import lombok.NonNull;

/**
 * The factory class {@link PinFactory} holds methods for creating lists of possible pins
 */
public final class PinFactory
{
	/**
	 * Private constructor to prevent instantiation
	 */
	private PinFactory()
	{
	}

	/**
	 * Creates a new list of pins formatted from the provided local dates and date patterns
	 *
	 * @param localDates
	 *            the list of local dates to be formatted
	 * @param datePatterns
	 *            the list of date patterns to apply
	 * @return a sorted list of formatted date strings
	 */
	public static List<String> newPins(@NonNull List<LocalDate> localDates,
		@NonNull List<String> datePatterns)
	{
		List<String> result = ListFactory.newArrayList();

		for (LocalDate localDate : localDates)
		{
			for (String datePattern : datePatterns)
			{
				result.add(localDate.format(DateTimeFormatter.ofPattern(datePattern)));
			}
		}
		result.sort(Comparator.naturalOrder());
		return result;
	}
}
