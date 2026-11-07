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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The serial number of the certificates that
 * {@link CertFactory#newX509CertificateV3(KeyPair, X500Name, int, X500Name, String, org.bouncycastle.asn1.x509.Extension...)}
 * makes (#118). RFC 5280 section 4.1.2.2 asks for a serial number that is unique per issuer, and
 * the CA/Browser Forum baseline for at least 64 bits from a cryptographically secure generator.
 */
class CertFactorySerialNumberTest
{

	private static final X500Name NAME = new X500Name("CN=Serial Number");

	/** an elliptic curve key, because its signature is fast enough for many certificates */
	private static KeyPair keyPair;

	/**
	 * Two certificates made in one millisecond of the clock
	 *
	 * @param millisecond
	 *            the millisecond both were made in
	 * @param first
	 *            the first certificate
	 * @param second
	 *            the second certificate
	 */
	record SameMillisecond(long millisecond, X509Certificate first, X509Certificate second) {
	}

	@BeforeAll
	static void setUp() throws Exception
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC",
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		keyPair = generator.generateKeyPair();
	}

	private static X509Certificate newCertificate() throws Exception
	{
		return CertFactory.newX509CertificateV3(keyPair, NAME, 1, NAME, "SHA256withECDSA");
	}

	/**
	 * Calls the overload twice, again and again, until both calls fall into one millisecond of the
	 * clock: the clock reads the same before the first and after the second.
	 *
	 * @return the two certificates and their millisecond
	 * @throws Exception
	 *             if a certificate cannot be made
	 */
	private static SameMillisecond twoCertificatesInOneMillisecond() throws Exception
	{
		for (int attempt = 0; attempt < 10_000; attempt++)
		{
			long before = System.currentTimeMillis();
			X509Certificate first = newCertificate();
			X509Certificate second = newCertificate();
			long after = System.currentTimeMillis();
			if (before == after)
			{
				return new SameMillisecond(before, first, second);
			}
		}
		throw new AssertionError("10000 attempts made no two certificates in one millisecond");
	}

	/**
	 * Today two certificates made in one millisecond get the same serial number, and it is that
	 * millisecond
	 *
	 * @throws Exception
	 *             if a certificate cannot be made
	 */
	@Test
	void twoCertificatesMadeInOneMillisecond_getTheSameSerialNumber_theMillisecond()
		throws Exception
	{
		SameMillisecond made = twoCertificatesInOneMillisecond();

		assertEquals(BigInteger.valueOf(made.millisecond()), made.first().getSerialNumber());
		assertEquals(made.first().getSerialNumber(), made.second().getSerialNumber());
	}
}
