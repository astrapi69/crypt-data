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

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.experimental.FieldDefaults;

/**
 * The enum {@link KeyStringEntry} holds prefixes for PEM value entries
 */
@Getter
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public enum KeyStringEntry
{
	/** The prefix for the begin of a private key */
	BEGIN_PRIVATE_KEY_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.PRIVATE_KEY_NAME
		+ KeyStringEntry.FIVE_HYPHENS),
	/** The prefix for the begin of a public key */
	BEGIN_PUBLIC_KEY_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.PRIVATE_KEY_NAME
		+ KeyStringEntry.FIVE_HYPHENS),
	/** The prefix for the begin of a RSA private key */
	BEGIN_RSA_PRIVATE_KEY_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.RSA_PRIVATE_KEY_NAME
		+ KeyStringEntry.PEM_KEY_NAME_SUFFIX),
	/** The prefix for the begin of a RSA public key */
	BEGIN_RSA_PUBLIC_KEY_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.RSA_PUBLIC_KEY_NAME
		+ KeyStringEntry.PEM_KEY_NAME_SUFFIX),
	/** The prefix for the begin of a DSA private key */
	BEGIN_DSA_PRIVATE_KEY_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.DSA_PRIVATE_KEY_NAME
		+ KeyStringEntry.PEM_KEY_NAME_SUFFIX),
	/** The prefix for the begin of a PGP private key */
	BEGIN_PGP_PRIVATE_KEY_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.PGP_PRIVATE_KEY_NAME
		+ KeyStringEntry.PEM_KEY_NAME_SUFFIX),
	/** The prefix for the begin of a PGP public key */
	BEGIN_PGP_PUBLIC_KEY_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.PGP_PUBLIC_KEY_NAME
		+ KeyStringEntry.PEM_KEY_NAME_SUFFIX),
	/** The prefix for the begin of a Elliptic Curve(EC) private key */
	BEGIN_EC_PRIVATE_KEY_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.EC_PRIVATE_KEY_NAME
		+ KeyStringEntry.PEM_KEY_NAME_SUFFIX),
	/** The prefix for the begin of a PKCS7 key */
	BEGIN_PKCS7_PREFIX(KeyStringEntry.PEM_KEY_BEGIN_PREFIX + PemType.PKCS7_KEY_NAME
		+ KeyStringEntry.PEM_KEY_NAME_SUFFIX),
	/** The prefix for the begin of a PKCS7 key */
	END_PKCS7_SUFFIX(KeyStringEntry.PEM_KEY_END_PREFIX + PemType.PKCS7_KEY_NAME
		+ KeyStringEntry.PEM_KEY_NAME_SUFFIX),
	/** The suffix for the end of a private key */
	END_PRIVATE_KEY_SUFFIX(
		KeyStringEntry.PEM_KEY_END_PREFIX + PemType.PRIVATE_KEY_NAME + KeyStringEntry.FIVE_HYPHENS),
	/** The suffix for the end of a public key */
	END_PUBLIC_KEY_SUFFIX(
		KeyStringEntry.PEM_KEY_END_PREFIX + PemType.PRIVATE_KEY_NAME + KeyStringEntry.FIVE_HYPHENS),
	/** The suffix for the end of a RSA private key */
	END_RSA_PRIVATE_KEY_SUFFIX(KeyStringEntry.PEM_KEY_END_PREFIX + PemType.RSA_PRIVATE_KEY_NAME
		+ KeyStringEntry.FIVE_HYPHENS),
	/** The suffix for the end of a RSA public key */
	END_RSA_PUBLIC_KEY_SUFFIX(KeyStringEntry.PEM_KEY_END_PREFIX + PemType.RSA_PUBLIC_KEY_NAME
		+ KeyStringEntry.FIVE_HYPHENS),
	/** The suffix for the end of a DSA private key */
	END_DSA_PRIVATE_KEY_SUFFIX(KeyStringEntry.PEM_KEY_END_PREFIX + PemType.DSA_PRIVATE_KEY_NAME
		+ KeyStringEntry.FIVE_HYPHENS),
	/** The suffix for the end of a PGP private key */
	END_PGP_PRIVATE_KEY_SUFFIX(KeyStringEntry.PEM_KEY_END_PREFIX + PemType.PGP_PRIVATE_KEY_NAME
		+ KeyStringEntry.FIVE_HYPHENS),
	/** The suffix for the end of a PGP public key */
	END_PGP_PUBLIC_KEY_SUFFIX(KeyStringEntry.PEM_KEY_END_PREFIX + PemType.PGP_PUBLIC_KEY_NAME
		+ KeyStringEntry.FIVE_HYPHENS),
	/** The suffix for the end of a Elliptic Curve(EC) private key */
	END_EC_PRIVATE_KEY_SUFFIX(KeyStringEntry.PEM_KEY_END_PREFIX + PemType.EC_PRIVATE_KEY_NAME
		+ KeyStringEntry.FIVE_HYPHENS);

	/** The Constant PEM_KEY_NAME_PREFIX. */
	private static final String FIVE_HYPHENS = "-----";
	/** The Constant PEM_KEY_BEGIN_PREFIX. */
	private static final String PEM_KEY_BEGIN_PREFIX = FIVE_HYPHENS + "BEGIN ";
	/** The Constant PEM_KEY_BEGIN_PREFIX. */
	private static final String PEM_KEY_END_PREFIX = FIVE_HYPHENS + "END ";
	/** The Constant PEM_KEY_PREFIX. */
	private static final String PEM_KEY_NAME_SUFFIX = FIVE_HYPHENS + "\n";

	/** The value the PEM entry */
	String value;
}
