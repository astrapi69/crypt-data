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
package io.github.astrapi69.crypto.key.reader;

import java.util.Arrays;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.FieldDefaults;

/**
 * The enum {@link PemType} holds the type names of PEM value entries
 */
@Getter
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public enum PemType
{
	RSA_PRIVATE_KEY(PemType.RSA_PRIVATE_KEY_NAME), PRIVATE_KEY(
		PemType.PRIVATE_KEY_NAME), RSA_PUBLIC_KEY(PemType.RSA_PUBLIC_KEY_NAME), PUBLIC_KEY(
			PemType.PUBLIC_KEY_NAME), DSA_PRIVATE_KEY(PemType.DSA_PRIVATE_KEY_NAME), X509_CRL(
				PemType.X509_CRL_NAME), CERTIFICATE(PemType.CERTIFICATE_NAME), CERTIFICATE_REQUEST(
					PemType.CERTIFICATE_REQUEST_NAME), NEW_CERTIFICATE_REQUEST(
						PemType.NEW_CERTIFICATE_REQUEST_NAME), PKCS7_KEY(
							PemType.PKCS7_KEY_NAME), EC_PRIVATE_KEY(
								PemType.EC_PRIVATE_KEY_NAME), PGP_PRIVATE_KEY(
									PemType.PGP_PRIVATE_KEY_NAME), PGP_PUBLIC_KEY(
										PemType.PGP_PUBLIC_KEY_NAME), UNKNOWN_TYPE(
											PemType.UNKNOWN_TYPE_NAME);

	/** The Constant PRIVATE_KEY_NAME. */
	public static final String UNKNOWN_TYPE_NAME = "UNKNOWN TYPE";
	/** The Constant PRIVATE_KEY_NAME. */
	public static final String PRIVATE_KEY_NAME = "PRIVATE KEY";
	/** The Constant PUBLIC_KEY_NAME. */
	public static final String PUBLIC_KEY_NAME = "PUBLIC KEY";
	/** The Constant RSA_PRIVATE_KEY_NAME. */
	public static final String RSA_PRIVATE_KEY_NAME = "RSA " + PRIVATE_KEY_NAME;
	/** The Constant RSA_PUBLIC_KEY_NAME. */
	public static final String RSA_PUBLIC_KEY_NAME = "RSA " + PUBLIC_KEY_NAME;
	/** The Constant DSA_PRIVATE_KEY_NAME. */
	public static final String DSA_PRIVATE_KEY_NAME = "DSA " + PRIVATE_KEY_NAME;
	/** The Constant X509_CRL_NAME. */
	public static final String X509_CRL_NAME = "X509 CRL";
	/** The Constant CERTIFICATE_NAME. */
	public static final String CERTIFICATE_NAME = "CERTIFICATE";
	/** The Constant CERTIFICATE_REQUEST_NAME. */
	public static final String CERTIFICATE_REQUEST_NAME = CERTIFICATE_NAME + " REQUEST";
	/** The Constant NEW_CERTIFICATE_REQUEST_NAME. */
	public static final String NEW_CERTIFICATE_REQUEST_NAME = "NEW " + CERTIFICATE_REQUEST_NAME;
	/** The Constant PKCS7_KEY_NAME. */
	public static final String PKCS7_KEY_NAME = "PKCS7";
	/** The Constant EC_PRIVATE_KEY_NAME. */
	public static final String EC_PRIVATE_KEY_NAME = "EC " + PRIVATE_KEY_NAME;
	/** The Constant PGP_PRIVATE_KEY_NAME. */
	public static final String PGP_PRIVATE_KEY_NAME = "PGP " + PRIVATE_KEY_NAME + " BLOCK";
	/** The Constant PGP_PUBLIC_KEY_NAME. */
	public static final String PGP_PUBLIC_KEY_NAME = "PGP " + PUBLIC_KEY_NAME + " BLOCK";

	/** The name the PEM entry */
	String name;

	public static PemType toPemType(String name)
	{
		return Arrays.stream(PemType.values()).filter(pemType -> pemType.getName().equals(name))
			.findFirst().orElse(PemType.UNKNOWN_TYPE);
	}
}
