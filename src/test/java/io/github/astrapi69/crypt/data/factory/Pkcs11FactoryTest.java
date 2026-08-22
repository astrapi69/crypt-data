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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link Pkcs11Factory}.
 * <p>
 * Requires a configured PKCS#11 module to run against - skips itself (rather than failing) if none
 * is available, since a PKCS#11 module is external test infrastructure (e.g. SoftHSM2), not
 * something these tests can set up themselves. To run these tests: install SoftHSM2, initialize a
 * token, and set the {@code PKCS11_TEST_CONFIG} system property to a SunPKCS11 config file pointing
 * at it (see the class Javadoc on {@link Pkcs11Factory} for the config file format).
 */
public class Pkcs11FactoryTest
{

	private static final String PIN = "123456";

	private static String configPath;

	@BeforeAll
	static void checkPkcs11Available()
	{
		configPath = System.getProperty("PKCS11_TEST_CONFIG");
		// note: gradle forwards an unset property as an empty string, and new File("").exists()
		// is true on current JDKs, so require a real, non-blank regular file
		assumeTrue(configPath != null && !configPath.isBlank() && new File(configPath).isFile(),
			"No PKCS#11 test config available (set -DPKCS11_TEST_CONFIG=<path>) - skipping");
	}

	/**
	 * Test method for {@link Pkcs11Factory#newProvider(String)} and
	 * {@link Pkcs11Factory#newKeyStore(Provider, char[])}
	 */
	@Test
	public void testNewProviderAndKeyStore() throws Exception
	{
		final Provider provider = Pkcs11Factory.newProvider(configPath);
		assertNotNull(provider);

		final KeyStore keyStore = Pkcs11Factory.newKeyStore(provider, PIN.toCharArray());
		assertNotNull(keyStore);
	}

	/**
	 * Test method proving a key pair generated via a {@link Pkcs11Factory}-configured provider is
	 * actually usable for signing/verifying (i.e. the provider is wired correctly end-to-end, not
	 * just constructible)
	 */
	@Test
	public void testGeneratedKeyPairIsUsableForSigning() throws Exception
	{
		final Provider provider = Pkcs11Factory.newProvider(configPath);

		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
		keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();

		final byte[] data = "the quick brown fox".getBytes("UTF-8");

		final Signature signer = Signature.getInstance("SHA256withECDSA", provider);
		signer.initSign(keyPair.getPrivate());
		signer.update(data);
		final byte[] signature = signer.sign();

		final Signature verifier = Signature.getInstance("SHA256withECDSA", provider);
		verifier.initVerify(keyPair.getPublic());
		verifier.update(data);

		assertTrue(verifier.verify(signature));
	}

}
