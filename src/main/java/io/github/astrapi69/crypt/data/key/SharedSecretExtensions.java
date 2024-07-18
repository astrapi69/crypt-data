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
package io.github.astrapi69.crypt.data.key;

import io.github.astrapi69.crypt.data.model.SharedSecretInfo;
import io.github.astrapi69.crypt.data.model.SharedSecretModel;

/**
 * The class {@link SharedSecretExtensions} provides methods to convert between
 * {@link SharedSecretInfo} and {@link SharedSecretModel}.
 */
public class SharedSecretExtensions
{


	/**
	 * Converts a {@link SharedSecretInfo} object to a {@link SharedSecretModel} object.
	 *
	 * @param info
	 *            the {@link SharedSecretInfo} object to convert
	 * @return the converted {@link SharedSecretModel} object
	 */
	public static SharedSecretModel toModel(SharedSecretInfo info)
	{
		return SharedSecretModel.builder()
			.privateKey(KeyInfoExtensions.toPrivateKey(info.getPrivateKeyInfo()))
			.publicKey(KeyInfoExtensions.toPublicKey(info.getPublicKeyInfo()))
			.keyAgreementAlgorithm(info.getKeyAgreementAlgorithm())
			.secretKeyAlgorithm(info.getSecretKeyAlgorithm()).provider(info.getProvider())
			.cipherAlgorithm(info.getCipherAlgorithm()).iv(info.getIv()).build();
	}

	/**
	 * Converts a {@link SharedSecretModel} object to a {@link SharedSecretInfo} object.
	 *
	 * @param model
	 *            the {@link SharedSecretModel} object to convert
	 * @return the converted {@link SharedSecretInfo} object
	 */
	public static SharedSecretInfo toInfo(SharedSecretModel model)
	{
		return SharedSecretInfo.builder()
			.privateKeyInfo(KeyInfoExtensions.toKeyInfo(model.getPrivateKey()))
			.publicKeyInfo(KeyInfoExtensions.toKeyInfo(model.getPublicKey()))
			.keyAgreementAlgorithm(model.getKeyAgreementAlgorithm())
			.secretKeyAlgorithm(model.getSecretKeyAlgorithm()).provider(model.getProvider())
			.cipherAlgorithm(model.getCipherAlgorithm()).iv(model.getIv()).build();
	}

}
