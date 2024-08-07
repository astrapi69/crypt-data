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

import java.math.BigInteger;

import lombok.AccessLevel;
import lombok.Data;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

/**
 * The class {@link CertificateInfo} represents all the information for an X.509 certificate
 */
@Data
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
public class CertificateInfo
{
	/**
	 * Information about the private key
	 */
	@NonNull
	KeyInfo privateKeyInfo;

	/**
	 * Information about the public key
	 */
	@NonNull
	KeyInfo publicKeyInfo;

	/**
	 * The distinguished name information of the issuer
	 */
	@NonNull
	DistinguishedNameInfo issuer;

	/**
	 * The serial number of the certificate
	 */
	@NonNull
	BigInteger serial;

	/**
	 * The validity period of the certificate
	 */
	@NonNull
	Validity validity;

	/**
	 * The distinguished name information of the subject
	 */
	@NonNull
	DistinguishedNameInfo subject;

	/**
	 * The signature algorithm used to sign the certificate
	 */
	@NonNull
	String signatureAlgorithm;

	/**
	 * The version of the certificate
	 */
	Integer version;

	/**
	 * The extensions added in X.509 V3 certificate
	 */
	ExtensionInfo[] extensions;
}
