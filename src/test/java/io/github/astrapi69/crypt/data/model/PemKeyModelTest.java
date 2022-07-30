package io.github.astrapi69.crypt.data.model;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.PublicKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PemObjectReader;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.crypto.key.PemType;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link PemKeyModel}
 */
public class PemKeyModelTest
{
	File derDir;
	File pemDir;

	PrivateKey privateKey;

	File privateKeyDerFile;
	File privateKeyPemFile;
	PublicKey publicKey;
	File publicKeyPemFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privateKeyPemFile = new File(pemDir, "private.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		publicKeyPemFile = new File(pemDir, "public.pem");
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);
	}

	/**
	 * Test method for {@link PemKeyModel} constructors and builders
	 */
	@Test
	public final void testConstructors() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		File keyFile;
		PemKeyModel keyModel;
		PrivateKey privateKeyFromModel;
		PublicKey publicKeyFromModel;
		X509Certificate certificate;
		X509Certificate certificateFromModel;
		PemObject pemObject;
		// new scenario...
		// @formatter:off
		keyModel = PemKeyModel
			.builder()
			.pemEncoded(PrivateKeyExtensions.toPemFormat(privateKey))
			.keyType(PemType.RSA_PRIVATE_KEY)
			.algorithm(privateKey.getAlgorithm()).build();
		// @formatter:on
		pemObject = PemObjectReader.getPemObject(keyModel.getPemEncoded());
		privateKeyFromModel = PrivateKeyReader.readPrivateKey(pemObject, keyModel.getAlgorithm());
		assertEquals(privateKey, privateKeyFromModel);
		// new scenario...
		// @formatter:off
		keyModel = PemKeyModel
			.builder()
			.pemEncoded(PublicKeyExtensions.toPemFormat(publicKey))
			.keyType(PemType.PUBLIC_KEY)
			.algorithm(publicKey.getAlgorithm()).build();
		// @formatter:on
		pemObject = PemObjectReader.getPemObject(keyModel.getPemEncoded());
		publicKeyFromModel = PublicKeyReader.readPublicKey(pemObject, keyModel.getAlgorithm());
		assertEquals(publicKey, publicKeyFromModel);
	}
}
