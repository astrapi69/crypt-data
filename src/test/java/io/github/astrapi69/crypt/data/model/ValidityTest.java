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


import java.time.ZonedDateTime;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;
import org.meanbean.test.BeanVerifier;


/**
 * Test class for {@link Validity} using JUnit 5 with parameterized tests. This class reads test
 * data from a CSV file and verifies the correctness of the {@link Validity#getValidityInDays()}
 * method.
 */
class ValidityTest
{

	/**
	 * Test method for {@link Validity} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanVerifier.forClass(Validity.class).editSettings().registerFactory(Validity.class, () -> {
			return Validity.builder().notBefore(ZonedDateTime.parse("2023-12-01T00:00:00Z"))
				.notAfter(ZonedDateTime.parse("2025-01-01T00:00:00Z")).build();
		}).edited().verify();
	}

}
