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

import java.security.PrivateKey;
import java.security.PublicKey;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

/**
 * The class {@code SharedSecretModel} represents a model for storing shared secret information. It
 * contains a private key, a public key, key agreement algorithm, secret key algorithm, security
 * provider, cipher algorithm, and initialization vector (IV).
 * <p>
 * This class is annotated with Lombok annotations to reduce boilerplate code:
 * <ul>
 * <li>{@link Data} generates getters, setters, toString, equals, and hashCode methods.</li>
 * <li>{@link NoArgsConstructor} generates a no-argument constructor.</li>
 * <li>{@link AllArgsConstructor} generates a constructor with all fields as parameters.</li>
 * <li>{@link SuperBuilder} generates a builder pattern for creating instances of this class.</li>
 * <li>{@link FieldDefaults} sets the default access level for fields to private.</li>
 * </ul>
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SharedSecretModel
{
	/**
	 * The private key used in the key agreement.
	 */
	PrivateKey privateKey;

	/**
	 * The public key used in the key agreement.
	 */
	PublicKey publicKey;

	/**
	 * The algorithm used for the key agreement.
	 */
	String keyAgreementAlgorithm;

	/**
	 * The algorithm used for the secret key.
	 */
	String secretKeyAlgorithm;

	/**
	 * The security provider used for the cryptographic operations.
	 */
	String provider;

	/**
	 * The algorithm used for the cipher.
	 */
	String cipherAlgorithm;

	/**
	 * The initialization vector (IV) used for the cipher.
	 */
	byte[] iv;
}
