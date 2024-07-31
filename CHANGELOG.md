## Change log
----------------------

Version 9.5
-------------

ADDED:

- new extension class KeySizeExtensions
- new extension class AlgorithmExtensions
- new method in class AlgorithmExtensions that validates a service name with a given algorithm
- new method in class AlgorithmExtensions that gets all algorithms from a service name
- new method in class AlgorithmExtensions that gets all service names from a given Provider
- new method for get the supported key sizes from KeyPairGenerator
- new method for get the supported key sizes from KeyGenerator
- new test dependency commons-csv
- new test dependency meanbean-factory
- new factory methods for create new X509Certificate objects

CHANGED:

- removed deprecated class references
- removed deprecated method references

Version 9.4
-------------

ADDED:

- new test dependency jsoup
- new conversion class SharedSecretExtensions for data classes SharedSecretInfo and SharedSecretModel
- new factory methods with SharedSecretInfo and SharedSecretModel in class KeyAgreementFactory
- new resolver method that resolves the algorithm of a given private key byte array in class PrivateKeyExtensions

CHANGED:

- update of dependency crypt-api to the new minor version 9.3
- update of test dependency jobj-contract-verifier to new version 5.2
- update of dependency commons-lang3 dependency version to 3.15.0
- remove of obsolete and unused files

Version 9.3
-------------

CHANGED:

- rename of module from crypt.data to io.github.astrapisixtynine.crypt.data
- update of dependency crypt-api  to the new minor version 9.2
- update of dependency commons-codec to the new patch version 1.17.1

Version 9.2
-------------

ADDED:

- new factory method with KeyPair object and the corresponding X509CertificateV3Info in CertFactory

CHANGED:

- remove of misleading field keyPairInfo in data class X509CertificateV1Info
- renamed obsolete class ExtensionInfo to ExtensionModel
- renamed class CertificateInfo to CertificateModel
- deleted deprecated and misspelled class Valitidy

Version 9.1
-------------

ADDED:

- new maven repository for dependency jobj-contract-verifier
- new libs.versions.toml file for new automatic catalog versions update
- new factory methods for create new X509Certificate objects
- new factory methods for create new KeyPair objects
- new data object class KeyPairInfo for create new KeyPair objects
- new data object class KeyStoreInfo for create new KeyStore objects
- new data object class DistinguishedNameInfo for create new DistinguishedName String objects
- new data object class ExtensionInfo for create new Extension objects
- new test dependency junit-jupiter-param in version 5.11.0-M2

CHANGED:

- update gradle to new version 8.9
- update of lombok dependency version to 1.18.34
- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 7.0.0.BETA1
- update of dependency commons-codec dependency version to 1.17.0
- update of dependency commons-io dependency version to 2.16.1
- update of dependency file-worker to new version to 17.3
- update of dependency guava version to new version 33.2.1-jre
- update of dependency silly-collection to new version to 27.1
- update of dependency silly-io to new version 3.1
- update of dependency silly-strings to new version 9.1
- update of dependency throwable to new version 3
- update of test dependency jobj-contract-verifier to new version 5.1
- update of test dependency junit-jupiter to new version 5.11.0-M2
- update of test dependency junit-platform-launcher to new version 1.11.0-M2

Version 9
-------------

CHANGED:

- update gradle to new version 8.7
- update of lombok dependency version to 1.18.32
- update of gradle-plugin dependency 'com.github.ben-manes.versions.gradle.plugin' to new version 0.51.0
- update of gradle-plugin dependency 'org.ajoberstar.grgit:grgit-gradle' to new version 5.2.2
- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 6.25.0
- update of crypt-api dependency to the new major version 9
- update of dependency commons-codec dependency version to 1.16.1
- update of dependency commons-lang3 dependency version to 3.14.0
- update of dependency commons-io dependency version to 2.16.0
- update of dependency guava version to new version 33.1.0-jre
- update of test dependency jobj-core to new version 8.2
- update of test dependency checksum-up to new version 3
- update of test dependency junit-jupiter-* to new version 5.10.2
- update of test dependency junit-platform-launcher to new version 1.10.2
- update javadoc parameters from privateKey to password in the factory classes

Version 8.5
-------------

ADDED:

- new factory method in factory extension class SecretKeyFactoryExtensions for create a SecretKey object

CHANGED:

- update of crypt-api dependency version to 8.6

Version 8.4
-------------

ADDED:

- new factory methods for generate shared secret
- new dependency 'org.junit.platform:junit-platform-launcher' for the next upgrade from gradle version

CHANGED:

- update gradle to new version 8.2.1
- update of crypt-api dependency version to 8.5
- update of test dependency junit-jupiter-* to new version 5.10.0-RC1

Version 8.3
-------------

ADDED:

- new module-info.java file that turns this library to a module
- new bean class for hold information of a certificate extension
- new factory class for create KeyPairGenerator objects
- new extension class ProviderExtensions for provide security provider information from the current jdk

CHANGED:

- update gradle to new version 8.2
- update of lombok dependency version to 1.18.28
- update of gradle-plugin dependency 'com.github.ben-manes.versions.gradle.plugin' to new version 0.47.0
- update of gradle-plugin dependency 'org.ajoberstar.grgit:grgit-gradle' to new version 5.2.0
- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 6.19.0
- replaced obsolete package.html files with new package-info.java files
- update of crypt-api dependency version to 8.4
- update of dependency commons-io dependency version to 1.16.0
- update of dependency commons-codec dependency version to 2.13.0
- update of dependency guava version to new version 32.1.1-jre
- update of dependency file-worker to new version to 11.6
- update of dependency silly-strings to new version 8.2
- update of dependency silly-io to new version 2.2
- update of dependency silly-collection to new version to 21
- update of test dependency jobj-core to new version 7.1
- update of test dependency time-machine to new version to 2.5
- update of test dependency randomizer to new version 9
- update of test dependency checksum-up to new version 2.2
- update of test dependency test-object to new version 7.2
- update of test dependency junit-jupiter-* to new version 5.10.0-M1
- update of test dependency 'com.github.meanbeanlib:meanbean' to new version 3.0.0-M9

Version 8.2
-------------

ADDED:

- new extension class for transform key objects to KeyModel object and back
- new method in class PrivateKeyReader for read private keys from a given KeyModel object

Version 8.1
-------------

CHANGED:

- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 6.10.0
- update of crypt-api dependency version to 8.3
- update of dependency file-worker to new version to 11.1
- update of dependency silly-collection to new version to 20
- update of test dependency test-object to new version 7.1
- update of test dependency jobj-core to new version 6.1
- update of test dependency checksum-up to new version 2.1

Version 8
-------------

ADDED:

- new unit test framework junit-jupiter-api(junit5)
- new extension class KeyExtensions for general operations of Key objects
- new method for transform a certificate to base64 string
- new method for transform a certificate to hexadecimal string
- new method for transform a pem string to a PemObject
- new method for transform a given PemObject to private key
- new method for transform a given PemObject to public key

CHANGED:

- update to jdk version 11
- update gradle to new version 7.5.1
- remove of unit test framework testng
- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 6.9.1
- update of crypt-api dependency version to 8.2
- update of dependency file-worker to new version to 11
- update of dependency silly-collections to new version to 19
- update of test dependency time-machine to new version to 2.1
- update of test dependency test-object to new version 7
- update of test dependency checksum-up to new version to 2

Version 7.11.1
-------------

ADDED:

- gradle-plugin dependency of 'org.ajoberstar.grgit:grgit-gradle' in version 4.4.1 for create git release tags
- new methods for get a private key from a given file that automatically resolves the algorithm

CHANGED:

- update gradle to new version 7.3.3
- update of com.github.ben-manes.versions.gradle.plugin to new version 0.42.0
- update of test dependency jobj-core to new version 5.3
- update of test dependency testng to new version 7.5
- update of test dependency test-objects to new version 5.7
- update of test dependency silly-io to new version 1.7
- update of test dependency jobj-contract-verifier to new version 3.5
- update of test dependency randomizer to new version 8.5
- renamed package 'io.github.astrapi69.crypto.factories' to 'io.github.astrapi69.crypto.factory'
- update of dependency crypt-api to new version to 7.7


Version 7.10
-------------

ADDED:

- new method in class PemObjectReader that transform a pem formatted key file to a PrivateKey object

CHANGED:

- update gradle to new version 7.3
- update of bcpkix-jdk15on dependency version to 1.70
- update of test dependency jobj-core to new version to 5
- replaced null returns with Optional.empty()

Version 7.9
-------------

ADDED:

- new method that transform a pem formatted key file to a String
- new model class for public and private keys
- improve gradle build performance by adding new gradle parameters for caching, parallel, configure on demand and file watch

CHANGED:

- update gradle to new version 7.3
- update of lombok dependency version to 1.18.22
- update of dependency guava version to new version 31.0.1-jre
- update of dependency file-worker to new version to 8.1
- update of dependency throw-able to new version to 1.7
- update of dependency silly-strings to new version to 8.1
- update of dependency silly-collections to new version to 18
- update of test dependency vintage-time to new version to 5.4
- removed deprecated class references
- removed unchecked class references

Version 7.8
-------------

ADDED:

- new dependency silly-collections in version 8.7
- new method for get the format of the key file
- new factory method for creation of pbe cipher
- new enum class PemType that holds the type names of PEM value entries
- new method for get the PemType from a given pem formatted key file
- new method for get the key object from the key file

CHANGED:

- update gradle to new version 7.2
- update of crypt-api dependency version to 7.6.1
- update of dependency file-worker to new version to 5.9
- changed all dependencies from groupid de.alpharogroup to new groupid io.github.astrapi69
- update gradle-plugin dependency of gradle.plugin.com.hierynomus.gradle.plugins:license-gradle-plugin to new version
  0.16.1
- update of dependency silly-strings to new version to 5.6
- update of dependency commons-io dependency version to 2.11.0
- update of test dependency silly-io to new version to 1.6
- update of test dependency test-objects to new version to 5.5
- update of test dependency jobj-core to new version to 3.9
- update of test dependency randomizer-core to new version to 8.3
- update of test dependency randomizer-data to new version to 8.3

Version 7.7
-------------

ADDED:

- new class AesRsaCryptModel for transfer of crypt data
- new factory methods for create symmetric keys

CHANGED:

- removed dependency com.rainerhahnekamp:sneakythrow
- update of dependency file-worker to new version to 5.8
- update of test dependency randomizer-core to new version to 8.2
- update of test dependency randomizer-data to new version to 8.2
- update of test dependency jobj-core to new version to 3.7
- update of test dependency vintage-time to new version to 5.3
- update of test dependency jobj-contract-verifier to new version to 3.4

Version 7.6
-------------

ADDED:

- new factory class CryptModelFactory for generate objects from class CryptModel
- new factory method in CryptModel with generic key argument
- new delegator methods for PublicKey in PublicKeyExtensions
- new delegator methods for PrivateKey in PrivateKeyExtensions
- new method that can get the private key from a password encrypted byte array
- new factory methods in CipherFactory for create a PBE Cipher object

CHANGED:

- update of gradle version to 6.9
- update of crypt-api dependency version to 7.5
- update of dependency commons-io dependency version to 2.10.0
- update of dependency guava version to 30.1.1-jre
- update of test dependency test-objects version to 5.4

Version 7.5
-------------

ADDED:

- added new factory class for generate pins from given dates and date patterns
- added new test dependency time-machine in version 1.2
- added new factory class for generate algorithm instances from given string

CHANGED:

- update of lombok dependency version to 1.18.20
- update of commons-lang3 dependency version to 3.12.0
- update of bcpkix-jdk15on dependency version to 1.69
- update of com.github.ben-manes.versions.gradle.plugin to new version 0.39.0
- changed to new package io.github.astrapi69

  Version 7.4

-------------

ADDED:

- added new factory method to KeyStoreFactory class
- new jar task for build manifest file
- added lombok dependency

CHANGED:

- update of gradle version to 6.7
- update of com.github.ben-manes.versions.gradle.plugin to new version 0.34.0

Version 7.3
-------------

ADDED:

- new build system gradle
- new decorator class for byte array object created

CHANGED:

- removed maven build system and all related files
- removed all lombok dependent imports

Version 7.2
-------------

ADDED:

- new generic class that holds a prefix and a suffix that can decorate an crypt object
- new decorator classes for character and string object created
- new FUNDING.yml file added for donations added

CHANGED:

- update of parent version to 5.3
- update of bouncycastle version to 1.64
- update of guava version to 28.1-jre
- extended CryptModel class with a List of decorators

Version 7.1
-------------

ADDED:

- new launch configuration for intellij created
- new restrictions for all operation rules added
- new unit tests for character operation rules created

Version 7
-------------

ADDED:

- this changelog file
- moved crypt-data to this project
