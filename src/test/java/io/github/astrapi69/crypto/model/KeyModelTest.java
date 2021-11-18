package io.github.astrapi69.crypto.model;

import io.github.astrapi69.crypto.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypto.compound.CompoundAlgorithm;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.evaluate.object.evaluators.EqualsHashCodeAndToStringEvaluator;
import io.github.astrapi69.random.object.RandomStringFactory;
import io.github.astrapi69.file.search.PathFinder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

public class KeyModelTest {
    File derDir;
    File pemDir;

    PrivateKey privateKey;

    File privateKeyDerFile;
    File privateKeyPemFile;

    /**
     * Sets up method will be invoked before every unit test method in this class
     */
    @BeforeMethod
    protected void setUp() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
        privateKeyPemFile = new File(pemDir, "private.pem");

        derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
        privateKeyDerFile = new File(derDir, "private.der");
        privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);
    }

    /**
     * Test method for {@link KeyModel} constructors and builders
     */
    @Test
    public final void testConstructors() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyModel keyModel = KeyModel.builder()
                .encoded(privateKey.getEncoded())
                .algorithm(privateKey.getAlgorithm())
                .build();

        PrivateKey privateKeyFromModel = PrivateKeyReader.readPrivateKey(keyModel.getEncoded(), keyModel.getAlgorithm());

        assertEquals(privateKey, privateKeyFromModel);
    }

    /**
     * Test method for {@link CryptModel#equals(Object)} , {@link CryptModel#hashCode()} and
     * {@link CryptModel#toString()}
     */
    @Test
    public void testEqualsHashcodeAndToStringWithClass()
            throws NoSuchMethodException, IllegalAccessException, InstantiationException,
            NoSuchFieldException, ClassNotFoundException, InvocationTargetException, IOException
    {
        boolean expected;
        boolean actual;

        actual = EqualsHashCodeAndToStringEvaluator
                .evaluateEqualsHashcodeAndToString(CryptModel.class, clazz -> {
                    return CryptModel.<Cipher, String, String> builder()
                            .key(RandomStringFactory.randomHexString(16).toUpperCase())
                            .algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(CompoundAlgorithm.SALT)
                            .iterationCount(19).operationMode(Cipher.ENCRYPT_MODE)
                            .decorator(CryptObjectDecorator.<String>builder().prefix("s").suffix("s").build()).build();
                });
        expected = true;
        assertEquals(expected, actual);
    }
}
