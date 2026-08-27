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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Parity tests for the certificate creating entry points of {@link CertFactory}, and regression
 * tests for issue #28.
 * <p>
 * Every way of making a certificate has to make one for the same set of keys. One of them built its
 * content signer without naming bouncy castle, so the jdk provider answered instead and refused
 * every ec curve it does not implement - including prime239v1, which is what bouncy castle produces
 * when no curve is named at all.
 */
class CertFactoryCurveParityTest
{

	private static final X500Name NAME = new X500Name("CN=Curve Parity");

	@BeforeAll
	static void registerBouncyCastle()
	{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static KeyPair newEcKeyPair(final String curve) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC",
			BouncyCastleProvider.PROVIDER_NAME);
		if (curve != null)
		{
			generator.initialize(new ECGenParameterSpec(curve));
		}
		return generator.generateKeyPair();
	}

	/**
	 * The overload that takes a number of days is the one that did not name the provider. The
	 * curves that passed were exactly the ones the jdk implements, which is what gave it away.
	 *
	 * @param curve
	 *            the named curve to generate on
	 * @throws Exception
	 *             if key generation fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "secp256r1", "secp384r1", "secp521r1", "prime239v1", "secp256k1" })
	void aCertificateIsMadeForEveryCurveBouncyCastleCanSignWith(final String curve) throws Exception
	{
		KeyPair keyPair = newEcKeyPair(curve);

		X509Certificate certificate = CertFactory.newX509CertificateV3(keyPair, NAME, 365, NAME,
			"SHA256withECDSA");

		assertNotNull(certificate, curve + " must yield a certificate");
		assertDoesNotThrow(
			() -> certificate.verify(keyPair.getPublic(), BouncyCastleProvider.PROVIDER_NAME),
			curve + " must be signed by the key it names");
	}

	/**
	 * The plainest ec key pair there is: no curve named, so bouncy castle picks its own default of
	 * prime239v1. That one could not be certified at all, which is the sharpest form of the defect.
	 *
	 * @throws Exception
	 *             if key generation fails
	 */
	@org.junit.jupiter.api.Test
	void anEcKeyPairWithNoCurveNamedCanBeCertified() throws Exception
	{
		KeyPair keyPair = newEcKeyPair(null);

		X509Certificate certificate = CertFactory.newX509CertificateV3(keyPair, NAME, 365, NAME,
			"SHA256withECDSA");

		assertNotNull(certificate);
		assertDoesNotThrow(
			() -> certificate.verify(keyPair.getPublic(), BouncyCastleProvider.PROVIDER_NAME));
	}

	/**
	 * The point of the parity: the four ways of making a certificate from a key pair have to agree
	 * about which keys they can serve. Three of them named the provider and one did not, so they
	 * disagreed for exactly the curves the jdk does not implement.
	 *
	 * @param curve
	 *            the named curve to generate on
	 * @throws Exception
	 *             if key generation fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "secp256r1", "prime239v1", "secp256k1" })
	void everyEntryPointServesTheSameKeys(final String curve) throws Exception
	{
		KeyPair keyPair = newEcKeyPair(curve);
		Date notBefore = new Date(0L);
		Date notAfter = new Date(1_000_000_000_000L);

		assertNotNull(CertFactory.newX509CertificateV1(keyPair, NAME, BigInteger.ONE, notBefore,
			notAfter, NAME, "SHA256withECDSA"), curve + " must be servable by the v1 entry point");
		assertNotNull(CertFactory.newX509CertificateV3(keyPair, NAME, BigInteger.ONE, notBefore,
			notAfter, NAME, "SHA256withECDSA"),
			curve + " must be servable by the dated v3 entry point");
		assertNotNull(CertFactory.newX509CertificateV3(keyPair, NAME, 365, NAME, "SHA256withECDSA"),
			curve + " must be servable by the days v3 entry point");
	}

	/**
	 * What the days overload builds is a version 3 certificate, and it stays one - the provider is
	 * the only thing that changes here.
	 *
	 * @throws Exception
	 *             if key generation fails
	 */
	@org.junit.jupiter.api.Test
	void theDaysOverloadStillBuildsAVersionThreeCertificate() throws Exception
	{
		KeyPair keyPair = newEcKeyPair("secp256r1");

		X509Certificate certificate = CertFactory.newX509CertificateV3(keyPair, NAME, 365, NAME,
			"SHA256withECDSA");

		assertEquals(3, certificate.getVersion(), "the v3 entry point must build a v3 certificate");
		assertEquals(NAME.toString(), certificate.getSubjectX500Principal().getName());
	}
}
