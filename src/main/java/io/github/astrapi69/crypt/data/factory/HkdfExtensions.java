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

import java.util.Objects;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * The factory class {@link HkdfExtensions} holds methods for deriving key material with HKDF
 * (HMAC-based Extract-and-Expand Key Derivation Function, RFC 5869). Use this to turn a raw
 * key-agreement shared secret (e.g. from X25519/ECDH) into a properly sized symmetric key, instead
 * of using the raw shared secret bytes directly.
 */
public final class HkdfExtensions
{

	private HkdfExtensions()
	{
	}

	/**
	 * Derives a key of the given length from the given input key material, salt and context info,
	 * using HKDF with SHA-256.
	 *
	 * @param inputKeyMaterial
	 *            the input key material, e.g. a raw Diffie-Hellman/ECDH/X25519 shared secret
	 * @param salt
	 *            the salt, may be {@code null} or empty (RFC 5869 substitutes a zero-filled salt in
	 *            that case)
	 * @param info
	 *            optional context/application-specific information to bind the derived key to, may
	 *            be {@code null}
	 * @param outputLength
	 *            the desired length in bytes of the derived key
	 * @return the derived key
	 */
	public static byte[] deriveKey(final byte[] inputKeyMaterial, final byte[] salt,
		final byte[] info, final int outputLength)
	{
		Objects.requireNonNull(inputKeyMaterial);
		final HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
		generator.init(new HKDFParameters(inputKeyMaterial, salt, info));
		final byte[] output = new byte[outputLength];
		generator.generateBytes(output, 0, outputLength);
		return output;
	}

}
