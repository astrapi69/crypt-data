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
package io.github.astrapi69.crypt.data.algorithm;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The class {@code AlgorithmValidatorTest} provides unit tests for the {@link AlgorithmValidator}
 * class
 */
class AlgorithmValidatorTest
{

	@BeforeAll
	static void setUp()
	{
		// Ensuring that some default algorithms are registered for the tests
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	/**
	 * Test for a valid algorithm
	 */
	@Test
	void testIsValid()
	{
		assertTrue(AlgorithmValidator.isValid("Cipher", "AES"));
	}

	/**
	 * Test for an invalid algorithm
	 */
	@Test
	void testIsInvalid()
	{
		assertFalse(AlgorithmValidator.isValid("Cipher", "InvalidAlgorithm"));
	}

	/**
	 * Test for an invalid service name
	 */
	@Test
	void testInvalidService()
	{
		assertFalse(AlgorithmValidator.isValid("InvalidService", "AES"));
	}
}
