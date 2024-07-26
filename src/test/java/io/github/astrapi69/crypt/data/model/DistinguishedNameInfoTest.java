package io.github.astrapi69.crypt.data.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;

/**
 * Test class for {@link DistinguishedNameInfo}
 */
class DistinguishedNameInfoTest
{

	/**
	 * Test for {@link DistinguishedNameInfo#toDistinguishedNameInfo(String)}
	 */
	@Test
	public void testToDistinguishedNameInfo()
	{
		String representableString = "C=US, ST=California, L=San Francisco, O=MyOrg, OU=MyUnit, CN=John Doe";

		DistinguishedNameInfo dnInfo = DistinguishedNameInfo
			.toDistinguishedNameInfo(representableString);

		assertEquals("US", dnInfo.getCountryCode());
		assertEquals("California", dnInfo.getState());
		assertEquals("San Francisco", dnInfo.getLocation());
		assertEquals("MyOrg", dnInfo.getOrganisation());
		assertEquals("MyUnit", dnInfo.getOrganisationUnit());
		assertEquals("John Doe", dnInfo.getCommonName());
	}

	/**
	 * Test for {@link DistinguishedNameInfo#toRepresentableString()}
	 */
	@Test
	public void testToRepresentableString()
	{
		String actual;
		String expected;
		DistinguishedNameInfo certificateAttributes;

		certificateAttributes = DistinguishedNameInfo.builder().build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "";
		assertEquals(actual, expected);

		certificateAttributes = DistinguishedNameInfo.builder().countryCode("GR").build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "C=GR";
		assertEquals(actual, expected);

		certificateAttributes = DistinguishedNameInfo.builder().countryCode("GR").state("Pieria")
			.build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "ST=Pieria,C=GR";
		assertEquals(actual, expected);

		certificateAttributes = DistinguishedNameInfo.builder().countryCode("GR").state("Pieria")
			.organisation("Alpha Ro Group Ltd").build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "O=Alpha Ro Group Ltd,ST=Pieria,C=GR";
		assertEquals(actual, expected);

		certificateAttributes = DistinguishedNameInfo.builder().countryCode("GR").state("Pieria")
			.organisation("Alpha Ro Group Ltd").organisationUnit("Certificate Authority").build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "OU=Certificate Authority,O=Alpha Ro Group Ltd,ST=Pieria,C=GR";
		assertEquals(actual, expected);

		certificateAttributes = DistinguishedNameInfo.builder().countryCode("GR").state("Pieria")
			.organisation("Alpha Ro Group Ltd").organisationUnit("Certificate Authority")
			.commonName("asterios.raptis@web.de").build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "CN=asterios.raptis@web.de,OU=Certificate Authority,O=Alpha Ro Group Ltd,ST=Pieria,C=GR";
		assertEquals(actual, expected);
	}

	/**
	 * Test for default values
	 */
	@Test
	void testDefaultValues()
	{
		DistinguishedNameInfo dnInfo = DistinguishedNameInfo.builder().build();

		assertNull(dnInfo.getCountryCode());
		assertNull(dnInfo.getState());
		assertNull(dnInfo.getLocation());
		assertNull(dnInfo.getOrganisation());
		assertNull(dnInfo.getOrganisationUnit());
		assertNull(dnInfo.getCommonName());
	}

	/**
	 * Test for X500Name conversion
	 */
	@Test
	void testToX500Name()
	{
		DistinguishedNameInfo dnInfo = DistinguishedNameInfo.builder().countryCode("US")
			.state("California").location("San Francisco").organisation("MyOrg")
			.organisationUnit("MyUnit").commonName("John Doe").build();

		X500Name x500Name = dnInfo.toX500Name();
		assertNotNull(x500Name);
	}
}
