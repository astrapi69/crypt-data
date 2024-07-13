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

import org.junit.jupiter.api.Test;

class DistinguishedNameInfoTest
{
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
		expected = "C=GR, ST=Pieria";
		assertEquals(actual, expected);

		certificateAttributes = DistinguishedNameInfo.builder().countryCode("GR").state("Pieria")
			.organisation("Alpha Ro Group Ltd").build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "C=GR, ST=Pieria, O=Alpha Ro Group Ltd";
		assertEquals(actual, expected);

		certificateAttributes = DistinguishedNameInfo.builder().countryCode("GR").state("Pieria")
			.organisation("Alpha Ro Group Ltd").organisationUnit("Certificate Authority").build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "C=GR, ST=Pieria, O=Alpha Ro Group Ltd, OU=Certificate Authority";
		assertEquals(actual, expected);

		certificateAttributes = DistinguishedNameInfo.builder().countryCode("GR").state("Pieria")
			.organisation("Alpha Ro Group Ltd").organisationUnit("Certificate Authority")
			.commonName("asterios.raptis@web.de").build();
		actual = DistinguishedNameInfo.toRepresentableString(certificateAttributes);
		expected = "C=GR, ST=Pieria, O=Alpha Ro Group Ltd, OU=Certificate Authority, CN=asterios.raptis@web.de";
		assertEquals(actual, expected);
	}

}