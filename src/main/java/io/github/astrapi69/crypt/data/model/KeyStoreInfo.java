package io.github.astrapi69.crypt.data.model;

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
public class KeyStoreInfo
{
	@NonNull
	private String distinguishedName;
	@NonNull
	private String keyAlgorithm;
	private int keySize;
	@NonNull
	private String keystoreFilePath;
	@NonNull
	private String keystorePassword;
	@NonNull
	private String keyPassword;
	private int validityDays;
	@NonNull
	private KeyModel certificateKeyModel;
	@NonNull
	private KeyPairInfo keyPairInfo;
}
