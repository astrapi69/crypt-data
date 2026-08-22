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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Parameterized tests for the edge cases of {@link DistinguishedNameInfo}: malformed parts in the
 * representable string, empty attribute values and the null contract of
 * {@link DistinguishedNameInfo#toX500Name(DistinguishedNameInfo)}
 */
class DistinguishedNameInfoEdgeCasesParameterizedTest
{

	/**
	 * One representable string that contains parts that are not "key=value" pairs
	 *
	 * @param representableString
	 *            the string to parse
	 * @param expectedCommonName
	 *            the expected common name
	 * @param expectedCountryCode
	 *            the expected country code
	 * @param expectedOrganisation
	 *            the expected organisation
	 */
	record MalformedPartCase(String representableString, String expectedCommonName,
		String expectedCountryCode, String expectedOrganisation) {
	}

	/**
	 * One pair of common name and organisation unit of which some may be empty
	 *
	 * @param commonName
	 *            the common name, may be null or empty
	 * @param organisationUnit
	 *            the organisation unit, may be null or empty
	 * @param expected
	 *            the expected representable string
	 */
	record EmptyValueCase(String commonName, String organisationUnit, String expected) {
	}

	static Stream<MalformedPartCase> malformedPartCases()
	{
		return Stream.of(
			new MalformedPartCase("CN=John Doe, garbage without equals sign, C=US", "John Doe",
				"US", null),
			new MalformedPartCase("CN=Jane=Doe, O=Org", null, null, "Org"),
			new MalformedPartCase("CN=Only", "Only", null, null),
			new MalformedPartCase("", null, null, null));
	}

	/**
	 * Test method for {@link DistinguishedNameInfo#toDistinguishedNameInfo(String)}: parts that are
	 * not exactly one "key=value" pair are skipped
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("malformedPartCases")
	void toDistinguishedNameInfoSkipsMalformedParts(final MalformedPartCase testCase)
	{
		DistinguishedNameInfo actual = DistinguishedNameInfo
			.toDistinguishedNameInfo(testCase.representableString());

		assertEquals(testCase.expectedCommonName(), actual.getCommonName());
		assertEquals(testCase.expectedCountryCode(), actual.getCountryCode());
		assertEquals(testCase.expectedOrganisation(), actual.getOrganisation());
		assertNull(actual.getState());
		assertNull(actual.getLocation());
		assertNull(actual.getOrganisationUnit());
	}

	static Stream<EmptyValueCase> emptyValueCases()
	{
		return Stream.of(new EmptyValueCase("John", "", "CN=John"),
			new EmptyValueCase("", "Unit", "OU=Unit"), new EmptyValueCase("", "", ""),
			new EmptyValueCase(null, "Unit", "OU=Unit"),
			new EmptyValueCase("John", null, "CN=John"),
			new EmptyValueCase("John", "Unit", "CN=John,OU=Unit"));
	}

	/**
	 * Test method for {@link DistinguishedNameInfo#toRepresentableString()}: null and empty values
	 * are left out
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("emptyValueCases")
	void toRepresentableStringOmitsEmptyValues(final EmptyValueCase testCase)
	{
		DistinguishedNameInfo distinguishedNameInfo = DistinguishedNameInfo.builder()
			.commonName(testCase.commonName()).organisationUnit(testCase.organisationUnit())
			.build();

		assertEquals(testCase.expected(), distinguishedNameInfo.toRepresentableString());
		assertEquals(testCase.expected(),
			DistinguishedNameInfo.toRepresentableString(distinguishedNameInfo));
	}

	/**
	 * Test method for {@link DistinguishedNameInfo#toX500Name(DistinguishedNameInfo)} and
	 * {@link DistinguishedNameInfo#toX500Name()}
	 */
	@Test
	void toX500Name()
	{
		DistinguishedNameInfo distinguishedNameInfo = DistinguishedNameInfo.builder()
			.countryCode("GR").state("Pieria").location("Katerini").organisation("ExampleOrg")
			.organisationUnit("ExampleUnit").commonName("Jane Doe").build();

		X500Name expected = new X500Name(distinguishedNameInfo.toRepresentableString());

		assertEquals(expected, distinguishedNameInfo.toX500Name());
		assertEquals(expected, DistinguishedNameInfo.toX500Name(distinguishedNameInfo));
		assertThrows(NullPointerException.class, () -> DistinguishedNameInfo.toX500Name(null));
	}
}
