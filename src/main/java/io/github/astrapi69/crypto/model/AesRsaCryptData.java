package io.github.astrapi69.crypto.model;

import lombok.AccessLevel;
import lombok.Data;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

import java.io.Serializable;

/**
 * The class {@link AesRsaCryptData} holds a byte array of the encrypted asymmetric key and the
 * byte array of the encrypted message that is encrypted with the symmetric key
 */
@Data
@RequiredArgsConstructor
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AesRsaCryptData implements Serializable
{
	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;
	@NonNull
	byte[] encryptedKey;
	@NonNull
	byte[] symmetricKeyEncryptedMessage;
}
