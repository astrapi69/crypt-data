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
package io.github.astrapi69.crypt.data.processor.certificate;


import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import io.github.astrapi69.crypt.data.algorithm.AlgorithmExtensions;
import io.github.astrapi69.crypt.data.algorithm.SignatureAlgorithmResolver;
import io.github.astrapi69.crypt.data.extension.LineAppender;
import io.github.astrapi69.crypt.data.factory.CertificateTestDataFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.model.CertificateInfo;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import lombok.extern.java.Log;

@Log
@Getter
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CertificateAlgorithmEntryRunner implements Runnable
{
	String keyPairAlgorithm;
	Set<Integer> keySizes;
	Set<String> signatureAlgorithms;
	File validSignatureAlgorithmsCsvFile;
	File invalidSignatureAlgorithmsCsvFile;
	boolean allKeysizes;

	public CertificateAlgorithmEntryRunner(final @NonNull String keyPairAlgorithm,
		final @NonNull Set<Integer> keySizes, final @NonNull File validSignatureAlgorithmsCsvFile,
		final @NonNull File invalidSignatureAlgorithmsCsvFile, boolean allKeysizes)
	{
		this.keyPairAlgorithm = keyPairAlgorithm;
		this.keySizes = keySizes;
		this.signatureAlgorithms = AlgorithmExtensions.getAlgorithms("Signature");
		this.validSignatureAlgorithmsCsvFile = validSignatureAlgorithmsCsvFile;
		this.invalidSignatureAlgorithmsCsvFile = invalidSignatureAlgorithmsCsvFile;
		this.allKeysizes = allKeysizes;
	}

	@Override
	public void run()
	{
		try
		{
			if (!keySizes.isEmpty())
			{
				if (allKeysizes)
				{
					for (Integer keySize : keySizes)
					{
						KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairAlgorithm, keySize);
						PrivateKey privateKey = keyPair.getPrivate();
						PublicKey publicKey = keyPair.getPublic();

						for (String signatureAlgorithm : signatureAlgorithms)
						{
							processSignatureAlgorithm(keyPairAlgorithm, signatureAlgorithm,
								privateKey, publicKey, validSignatureAlgorithmsCsvFile,
								invalidSignatureAlgorithmsCsvFile);
						}
					}
				}
				else
				{
					List<Integer> keySizesCopy = new ArrayList<>(keySizes);
					Integer keySize = keySizesCopy.get(0);
					KeyPair keyPair = KeyPairFactory.newKeyPair(keyPairAlgorithm, keySize);
					PrivateKey privateKey = keyPair.getPrivate();
					PublicKey publicKey = keyPair.getPublic();

					for (String signatureAlgorithm : signatureAlgorithms)
					{
						processSignatureAlgorithm(keyPairAlgorithm, signatureAlgorithm, privateKey,
							publicKey, validSignatureAlgorithmsCsvFile,
							invalidSignatureAlgorithmsCsvFile);
					}
				}
			}
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e)
		{
			log.log(Level.WARNING, "KeyPair generation failed for algorithm: " + keyPairAlgorithm,
				e);
		}
	}

	private void processSignatureAlgorithm(String keyPairAlgorithm, String signatureAlgorithm,
		PrivateKey privateKey, PublicKey publicKey, File validSignatureAlgorithmsCsvFile,
		File invalidSignatureAlgorithmsCsvFile)
	{

		CertificateAlgorithmEntry certificateAlgorithmEntry = CertificateAlgorithmEntry.builder()
			.keyPairAlgorithm(keyPairAlgorithm).signatureAlgorithm(signatureAlgorithm).build();

		CertificateInfo certificateInfo = CertificateInfo.builder()
			.privateKeyInfo(KeyInfoExtensions.toKeyInfo(privateKey))
			.publicKeyInfo(KeyInfoExtensions.toKeyInfo(publicKey))
			.issuer(CertificateTestDataFactory.newIssuerDistinguishedNameInfo())
			.subject(CertificateTestDataFactory.newSubjectDistinguishedNameInfo())
			.serial(CertificateTestDataFactory.newSerialNumber())
			.validity(CertificateTestDataFactory.newValidity())
			.signatureAlgorithm(signatureAlgorithm).version(3)
			.extensions(CertificateTestDataFactory.newExtensionInfos()).build();

		if (SignatureAlgorithmResolver.isAlgorithmValidForCertificate(certificateInfo))
		{
			appendToFile(validSignatureAlgorithmsCsvFile, certificateAlgorithmEntry);
		}
		else
		{
			appendToFile(invalidSignatureAlgorithmsCsvFile, certificateAlgorithmEntry);
		}
	}

	private void appendToFile(File file, CertificateAlgorithmEntry entry)
	{
		try
		{
			LineAppender.appendLines(file,
				entry.getKeyPairAlgorithm() + "," + entry.getSignatureAlgorithm());
		}
		catch (IOException e)
		{
			log.log(Level.WARNING, "IOException while appending entry to file: " + file.getName(),
				e);
		}
	}

}
