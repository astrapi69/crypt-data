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
	BEGIN_PRIVATE_KEY_PREFIX("-----BEGIN PRIVATE KEY-----"),
	/** The prefix for the begin of a rsa private key */
	BEGIN_RSA_PRIVATE_KEY_PREFIX("-----BEGIN " + KeyStringEntry.RSA_PRIVATE_KEY_NAME + "-----\n"),
	/** The suffix for the begin of a private key */
	END_PRIVATE_KEY_SUFFIX("-----END PRIVATE KEY-----"),
	/** The suffix for the begin of a rsa private key */
	END_RSA_PRIVATE_KEY_SUFFIX("\n-----END " + KeyStringEntry.RSA_PRIVATE_KEY_NAME + "-----"),
	/** The prefix for the begin of a rsa private key */
	RSA_PRIVATE_KEY(KeyStringEntry.RSA_PRIVATE_KEY_NAME);

	/** The Constant RSA_PRIVATE_KEY. */
	private static final String RSA_PRIVATE_KEY_NAME = "RSA PRIVATE KEY";
	/** The value the PEM entry */
	String value;
}
