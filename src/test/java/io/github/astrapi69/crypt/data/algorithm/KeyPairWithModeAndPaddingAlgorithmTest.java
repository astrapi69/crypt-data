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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairWithModeAndPaddingAlgorithm;

/**
 * Test class for enum {@link KeyPairWithModeAndPaddingAlgorithm}.
 */
public class KeyPairWithModeAndPaddingAlgorithmTest
{

	/**
	 * Test method for {@link KeyPairWithModeAndPaddingAlgorithm#getAlgorithm()}.
	 */
	@Test
	public void testGetAlgorithm()
	{
		assertEquals(
			KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding.getAlgorithm(),
			"RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		assertEquals(
			KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding.getAlgorithm(),
			"RSA/ECB/OAEPWithSHA256AndMGF1Padding");
		assertEquals(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_PKCS1PADDING.getAlgorithm(),
			"RSA/ECB/PKCS1Padding");
		assertEquals(KeyPairWithModeAndPaddingAlgorithm.DESede_CBC_PKCS5Padding.getAlgorithm(),
			"DESede/CBC/PKCS5Padding");

	}

}
