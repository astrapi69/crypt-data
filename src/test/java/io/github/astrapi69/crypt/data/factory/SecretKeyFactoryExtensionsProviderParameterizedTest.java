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

import java.security.Security;
import java.util.stream.Stream;

import javax.crypto.SecretKeyFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for {@link SecretKeyFactoryExtensions#newSecretKeyFactory(String, String)}
 * and the non-null contract of the factory methods
 */
class SecretKeyFactoryExtensionsProviderParameterizedTest
{

	/**
	 * One factory request
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param provider
	 *            the provider, may be null or empty for the default provider lookup
	 * @param expectedProviderName
	 *            the provider the factory must come from or null if any provider is fine
	 */
	record FactoryCase(String algorithm, String provider, String expectedProviderName) {
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

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	static Stream<FactoryCase> factoryCases()
	{
		return Stream.of(new FactoryCase("PBKDF2WithHmacSHA256", null, null),
			new FactoryCase("PBKDF2WithHmacSHA256", "", null),
			new FactoryCase("PBKDF2WithHmacSHA256", "SunJCE", "SunJCE"),
			new FactoryCase("PBKDF2WithHmacSHA1", "BC", "BC"));
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKeyFactory(String, String)} and
	 * {@link SecretKeyFactoryExtensions#newSecretKeyFactory(String)}
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             if the factory cannot be created
	 */
	@ParameterizedTest
	@MethodSource("factoryCases")
	void newSecretKeyFactory(final FactoryCase testCase) throws Exception
	{
		SecretKeyFactory actual = SecretKeyFactoryExtensions
			.newSecretKeyFactory(testCase.algorithm(), testCase.provider());

		assertEquals(testCase.algorithm(), actual.getAlgorithm());
		if (testCase.expectedProviderName() != null)
		{
			assertEquals(testCase.expectedProviderName(), actual.getProvider().getName());
		}
		else
		{
			// without a provider the result is the same as from the single argument method
			assertEquals(SecretKeyFactoryExtensions.newSecretKeyFactory(testCase.algorithm())
				.getProvider().getName(), actual.getProvider().getName());
		}
	}

	static Stream<NullArgumentCase> nullArgumentCases()
	{
		return Stream.of(
			new NullArgumentCase("newSecretKeyFactory(String)",
				() -> SecretKeyFactoryExtensions.newSecretKeyFactory(null)),
			new NullArgumentCase("newSecretKeyFactory(String, String)",
				() -> SecretKeyFactoryExtensions.newSecretKeyFactory(null, "SunJCE")));
	}

	/**
	 * Test method for the non-null contract of the factory methods
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
