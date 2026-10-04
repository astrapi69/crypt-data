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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

/**
 * The factory class {@link Pkcs11Factory} holds methods for configuring the JDK's built-in
 * {@code SunPKCS11} security provider against a PKCS#11 module (a hardware security module, smart
 * card, or software token such as SoftHSM2), and for opening its keystore. Once configured, the
 * returned {@link Provider} can be passed to any standard JCA factory method (
 * {@code KeyPairGenerator.getInstance(algorithm, provider)},
 * {@code Signature.getInstance(algorithm,
 * provider)}, etc.) to perform that operation on the token itself - private key material generated
 * or stored this way never leaves the token.
 * <p>
 * The config file passed to {@link #newProvider(String)} is a plain SunPKCS11 config file, e.g.
 *
 * <pre>
 * name = SoftHSM-Test
 * library = /usr/lib/softhsm/libsofthsm2.so
 * slotListIndex = 0
 * </pre>
 * <p>
 * See the <a href=
 * "https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html">PKCS#11
 * Reference Guide</a> for the full config file format.
 */
public final class Pkcs11Factory
{

	private Pkcs11Factory()
	{
	}

	/**
	 * Configures the JDK's {@code SunPKCS11} provider against the PKCS#11 module described by the
	 * given config file.
	 *
	 * @param configFilePath
	 *            the path to a SunPKCS11 config file
	 * @return the configured provider, not yet registered with {@link Security}
	 * @throws IllegalStateException
	 *             is thrown if the {@code SunPKCS11} provider is not available in the current JDK
	 */
	public static Provider newProvider(final String configFilePath)
	{
		final Provider baseProvider = Security.getProvider("SunPKCS11");
		if (baseProvider == null)
		{
			throw new IllegalStateException("SunPKCS11 provider not available in this JDK");
		}
		return baseProvider.configure(configFilePath);
	}

	/**
	 * Opens the PKCS#11 token's keystore via the given provider.
	 *
	 * @param provider
	 *            a provider configured by {@link #newProvider(String)}
	 * @param pin
	 *            the token's user PIN
	 * @return the opened keystore, giving access to the keys and certificates already stored on the
	 *         token
	 * @throws KeyStoreException
	 *             is thrown if the {@code PKCS11} keystore type is not supported by the given
	 *             provider
	 * @throws IOException
	 *             is thrown if the PIN is incorrect or the token is otherwise inaccessible
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a required algorithm for verifying the keystore's integrity is
	 *             unavailable
	 * @throws CertificateException
	 *             is thrown if any certificate on the token could not be loaded
	 */
	public static KeyStore newKeyStore(final Provider provider, final char[] pin)
		throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
	{
		final KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
		keyStore.load(null, pin);
		return keyStore;
	}

}
