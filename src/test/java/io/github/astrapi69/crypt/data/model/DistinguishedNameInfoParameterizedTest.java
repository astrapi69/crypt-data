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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test class for {@link DistinguishedNameInfo}
 */
class DistinguishedNameInfoParameterizedTest
{

	/**
	 * Provides test data for parameterized test
	 *
	 * @return a stream of arguments for parameterized test
	 */
	static Stream<String> provideDistinguishedNameInfoStrings()
	{
		return Stream.of("C=US, ST=California, L=San Francisco, O=MyOrg, OU=MyUnit, CN=John Doe",
			"C=GR, ST=Pieria, L=Katerini, O=ExampleOrg, OU=ExampleUnit, CN=Jane Doe",
			"C=FR, ST=Ile-de-France, L=Paris, O=AnotherOrg, OU=AnotherUnit, CN=John Smith");
	}

	/**
	 * Parameterized test for {@link DistinguishedNameInfo#toDistinguishedNameInfo(String)}
	 *
	 * @param representableString
	 *            the string to convert to {@link DistinguishedNameInfo}
	 */
	@ParameterizedTest
	@MethodSource("provideDistinguishedNameInfoStrings")
	void testToDistinguishedNameInfoParameterized(String representableString)
	{
		DistinguishedNameInfo dnInfo = DistinguishedNameInfo
			.toDistinguishedNameInfo(representableString);

		assertNotNull(dnInfo);
		assertNotNull(dnInfo.getCountryCode());
		assertNotNull(dnInfo.getState());
		assertNotNull(dnInfo.getLocation());
		assertNotNull(dnInfo.getOrganisation());
		assertNotNull(dnInfo.getOrganisationUnit());
		assertNotNull(dnInfo.getCommonName());
	}

	/**
	 * Parameterized test for {@link DistinguishedNameInfo#toRepresentableString()} using CSV data
	 *
	 * @param countryCode
	 *            the country code
	 * @param state
	 *            the state
	 * @param location
	 *            the location
	 * @param organisation
	 *            the organisation
	 * @param organisationUnit
	 *            the organisation unit
	 * @param commonName
	 *            the common name
	 * @param expected
	 *            the expected representable string
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/distinguishedNameInfoTestData.csv", delimiter = ';', numLinesToSkip = 1)
	void testToRepresentableStringParameterized(String countryCode, String state, String location,
		String organisation, String organisationUnit, String commonName, String expected)
	{
		DistinguishedNameInfo dnInfo = DistinguishedNameInfo.builder().countryCode(countryCode)
			.state(state).location(location).organisation(organisation)
			.organisationUnit(organisationUnit).commonName(commonName).build();

		String actual = DistinguishedNameInfo.toRepresentableString(dnInfo);
		assertEquals(expected, actual);
	}

}
