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

import java.math.BigInteger;
import java.time.ZonedDateTime;

import org.bouncycastle.asn1.x500.X500Name;

import io.github.astrapi69.crypt.data.model.DistinguishedNameInfo;
import io.github.astrapi69.crypt.data.model.Validity;
import io.github.astrapi69.random.number.RandomBigIntegerFactory;

/**
 * A factory class for generating test data related to certificates
 */
public class CertificateTestDataFactory
{

	/**
	 * Generates a new {@link X500Name} for the issuer with a common name of "Test Issuer"
	 *
	 * @return a new {@link X500Name} instance representing the issuer
	 */
	public static X500Name newIssuerX500Name()
	{
		return new X500Name("CN=Test Issuer");
	}

	/**
	 * Generates a new {@link X500Name} for the subject with a common name of "Test Subject"
	 *
	 * @return a new {@link X500Name} instance representing the subject
	 */
	public static X500Name newSubjectX500Name()
	{
		return new X500Name("CN=Test Subject");
	}

	/**
	 * Creates a new {@link DistinguishedNameInfo} for the issuer with predefined attributes
	 *
	 * @return a new {@link DistinguishedNameInfo} instance representing the issuer
	 */
	public static DistinguishedNameInfo newIssuerDistinguishedNameInfo()
	{
		String representableString = "C=US, ST=California, L=San Francisco, O=MyOrg, OU=MyUnit, CN=John Doe";
		return DistinguishedNameInfo.toDistinguishedNameInfo(representableString);
	}

	/**
	 * Creates a new {@link DistinguishedNameInfo} for the subject with predefined attributes
	 *
	 * @return a new {@link DistinguishedNameInfo} instance representing the subject
	 */
	public static DistinguishedNameInfo newSubjectDistinguishedNameInfo()
	{
		return DistinguishedNameInfo.builder().countryCode("GR").state("Pieria").location("Karitsa")
			.organisation("Alpha Ro Group Ltd").organisationUnit("Certificate Authority")
			.commonName("Alpha Robert").build();
	}

	/**
	 * Creates a new {@link Validity} instance with the validity period starting from the current
	 * date and time and lasting for one year
	 *
	 * @return a new {@link Validity} instance
	 */
	public static Validity newValidity()
	{
		ZonedDateTime now = ZonedDateTime.now();
		return Validity.builder().notBefore(now).notAfter(now.plusYears(1)).build();
	}

	/**
	 * Generates a new random {@link BigInteger} to be used as a serial number
	 *
	 * @return a random {@link BigInteger} instance
	 */
	public static BigInteger newSerialNumber()
	{
		return RandomBigIntegerFactory.randomBigInteger();
	}
}
