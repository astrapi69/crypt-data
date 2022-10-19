package io.github.astrapi69.crypt.data.model;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

import java.security.PrivateKey;
import java.security.PublicKey;

@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SharedSecretModel {
    PrivateKey privateKey;
    PublicKey publicKey;
    String algorithm;
    String secretKeyAlgorithm;
    String provider;
    String cipherTransformation;
    byte[] iv;
}
