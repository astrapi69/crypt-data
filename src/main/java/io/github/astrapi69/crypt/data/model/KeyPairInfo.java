package io.github.astrapi69.crypt.data.model;

import java.security.KeyPair;

import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

@Data
@RequiredArgsConstructor
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class KeyPairInfo
{
	String eCNamedCurveParameterSpecName;
	@NonNull
	String algorithm;
	String provider;
	int keySize;


	public static KeyPair newKeyPair(KeyPairInfo keyPairInfo) throws Exception
	{
		KeyPair keyPair;
		if (keyPairInfo.getECNamedCurveParameterSpecName() != null
			&& keyPairInfo.getProvider() != null)
		{
			keyPair = KeyPairFactory.newKeyPair(keyPairInfo.getECNamedCurveParameterSpecName(),
				keyPairInfo.getAlgorithm(), keyPairInfo.getProvider());
			return keyPair;
		}
		if (keyPairInfo.getECNamedCurveParameterSpecName() != null)
		{
			keyPair = KeyPairFactory.newKeyPair(keyPairInfo.getECNamedCurveParameterSpecName(),
				keyPairInfo.getAlgorithm(), "BC");
			return keyPair;
		}
		return KeyPairFactory.newKeyPair(keyPairInfo.getAlgorithm(), keyPairInfo.getKeySize());
	}
}
