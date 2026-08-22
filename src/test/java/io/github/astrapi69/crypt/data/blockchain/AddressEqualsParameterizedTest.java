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
package io.github.astrapi69.crypt.data.blockchain;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for the equals/hashCode contract of {@link Address}, including the null-field
 * branches that the constructor with arguments can never produce
 */
class AddressEqualsParameterizedTest
{

	private static final byte[] PUBLIC_KEY = { 1, 2, 3 };
	private static final byte[] HASH = { 9, 8, 7 };

	/**
	 * One equality comparison
	 *
	 * @param description
	 *            what is compared
	 * @param first
	 *            the object whose equals method is invoked
	 * @param second
	 *            the argument of the equals method
	 * @param expectedEqual
	 *            the expected result
	 */
	record EqualsCase(String description, Address first, Object second, boolean expectedEqual) {
	}

	private static Address newAddress(final String name, final byte[] publicKey, final byte[] hash)
	{
		Address address = new Address();
		address.setName(name);
		address.setPublicKey(publicKey);
		address.setHash(hash);
		return address;
	}

	static Stream<EqualsCase> equalsCases()
	{
		Address same = newAddress("foo", PUBLIC_KEY, HASH);
		return Stream.of(new EqualsCase("same instance", same, same, true),
			new EqualsCase("null", newAddress("foo", PUBLIC_KEY, HASH), null, false),
			new EqualsCase("other type", newAddress("foo", PUBLIC_KEY, HASH), "foo", false),
			new EqualsCase("identical fields", newAddress("foo", PUBLIC_KEY, HASH),
				newAddress("foo", PUBLIC_KEY.clone(), HASH.clone()), true),
			new EqualsCase("all fields null", new Address(), new Address(), true),
			new EqualsCase("first name null", newAddress(null, PUBLIC_KEY, HASH),
				newAddress("foo", PUBLIC_KEY, HASH), false),
			new EqualsCase("second name null", newAddress("foo", PUBLIC_KEY, HASH),
				newAddress(null, PUBLIC_KEY, HASH), false),
			new EqualsCase("both names null", newAddress(null, PUBLIC_KEY, HASH),
				newAddress(null, PUBLIC_KEY, HASH), true),
			new EqualsCase("names differ", newAddress("foo", PUBLIC_KEY, HASH),
				newAddress("bar", PUBLIC_KEY, HASH), false),
			new EqualsCase("public keys differ", newAddress("foo", PUBLIC_KEY, HASH),
				newAddress("foo", new byte[] { 3, 2, 1 }, HASH), false),
			new EqualsCase("first public key null", newAddress("foo", null, HASH),
				newAddress("foo", PUBLIC_KEY, HASH), false),
			new EqualsCase("hashes differ", newAddress("foo", PUBLIC_KEY, HASH),
				newAddress("foo", PUBLIC_KEY, new byte[] { 0 }), false),
			new EqualsCase("first hash null", newAddress("foo", PUBLIC_KEY, null),
				newAddress("foo", PUBLIC_KEY, HASH), false));
	}

	/**
	 * Test method for {@link Address#equals(Object)} and {@link Address#hashCode()}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("equalsCases")
	void equalsContract(final EqualsCase testCase)
	{
		assertEquals(testCase.expectedEqual(), testCase.first().equals(testCase.second()),
			testCase.description());
		if (testCase.second()instanceof Address other)
		{
			assertEquals(testCase.expectedEqual(), other.equals(testCase.first()),
				"symmetry: " + testCase.description());
			if (testCase.expectedEqual())
			{
				assertEquals(testCase.first().hashCode(), other.hashCode(), testCase.description());
			}
		}
	}
}
