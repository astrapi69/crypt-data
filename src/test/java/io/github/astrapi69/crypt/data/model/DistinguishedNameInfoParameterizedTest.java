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
