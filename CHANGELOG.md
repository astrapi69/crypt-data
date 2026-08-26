## Change log
----------------------

Version 12.1-SNAPSHOT
-------------

ADDED:

- PrivateKeyExtensions#toPkcs8PemFormat(PrivateKey), the counterpart of toPemFormat: the PKCS#8
  encoding under the PRIVATE KEY header that names it

CHANGED:

- build only: the Central Portal token is read from centralUsername / centralPassword in
  ~/.gradle/gradle.properties when the environment does not carry it, so a release prepared by
  hand no longer needs the token exported into a shell. CI keeps precedence.
- PrivateKeyExtensions#toPemFormat now says what it does: the traditional form of the key's own
  algorithm. Its javadoc claimed PKCS#1 for every key, and a key with no traditional form of its
  own was written under the PRIVATE KEY header - which means PKCS#8 - over content that had the
  PKCS#8 wrapper stripped. Such a key now keeps its PKCS#8 encoding, so the header and the bytes
  agree.

FIXED:

- PrivateKeyWriter#write(..., KeyFileFormat.PEM, KeyFormat.PKCS_8) wrote PKCS#1, for every key
  type. It routed through toPemFormat, which is a PKCS#1 method, so the caller got the traditional
  form under the traditional header - and for a key with no traditional form, PKCS#1 content under
  the PKCS#8 header, a file readable as neither. It now writes the PKCS#8 encoding under the
  PRIVATE KEY header. (#12)
- PrivateKeyWriter#write(..., KeyFileFormat.PEM, KeyFormat.PKCS_1) labelled every key
  RSA PRIVATE KEY, because it called fromPKCS1ToPemFormat, which takes bytes rather than a key and
  so cannot tell the algorithm. An EC or DSA key was written under the wrong header. It now goes
  through toPemFormat, which has the key and picks the header that belongs to it. (#12)
- Reading a PEM private key assumed RSA, so a valid EC, DSA, Ed25519, Ed448, X25519 or DH key was
  refused and PrivateKeyReader#validatePrivateKey called it invalid. A PKCS#8 file names its
  algorithm in its algorithm identifier and a traditional file names it in its header, so the
  algorithm is now read from the file. A file that holds no readable private key is still refused,
  and the refusal now names the file and what was found there instead. (#14)

KNOWN ISSUES:

- Reading a PEM private key of any algorithm other than RSA fails: the entry points that take no
  algorithm assume RSA, so PrivateKeyReader#validatePrivateKey answers false for a valid EC, DSA
  or Ed25519 key. Pass the algorithm explicitly until this is fixed. (#14)
- A DSA key written with KeyFormat.PKCS_1 carries only its private exponent, without p, q and g,
  so no reader can make a key out of it again. Write DSA keys as PKCS#8. (#15)


Version 12.0.0
-------------

CHANGED:

- module-info.java now exports the io.github.astrapi69.crypt.data.key package
  (KeyStoreExtensions, CertificateExtensions and the other key helpers), so JPMS consumers
  such as the mystic-crypt CLI can use it - previously only classpath consumers could.
  Also published standalone as release 11.2 (branch release/11.2: 11.1 plus only this export).
- BREAKING: three public utility classes now declare an explicit private constructor, removing the
  implicit public one they had before: SharedSecretExtensions, SignatureAlgorithmResolver (both
  public non-final, so instantiation AND subclassing break) and ProviderExtensions (already final,
  so only instantiation breaks). All three hold nothing but static methods; nothing in this repo
  instantiated them. This is what raises this release to 12.0.0.
- PrivateKeyReader#getPrivateKey(byte[]) and EncryptedPrivateKeyReader#getPrivateKey(File, String)
  no longer route their result through a local Optional variable. Both walk a list of candidate
  algorithms and returned on the first success, so the local could only ever hold Optional.empty()
  at the fall-through; each branch now returns Optional.of(...) directly and the method ends in
  Optional.empty(). Internal only, no behaviour change.
- test quality: 100% line and 100% branch coverage (also 100% instruction, complexity, method and
  class), up from 99.05%/98.28%, and a 100.00% PIT mutation score (779 of 779 mutants killed, no
  survivors), up from 98%. Coverage was reached by deleting dead code - null guards on values that
  cannot be null, two uncalled methods in a private nested class, a 26-line duplicate of an
  existing method - rather than by adding exclusions or tests without assertions. The last three
  surviving mutants were cleared in the round documented below, not argued away. Measured on the
  release tree: 1019 tests. See mystic-crypt/docs/TESTING.md for the strategy and
  mystic-crypt/docs/COVERAGE_EXCEPTIONS.md for the per-mutant reasoning.

FIXED:

- EncryptedPrivateKeyReader#getKeyPair(File, String) threw a NullPointerException for any file that
  contains no PEM object, because PEMParser#readObject() returns null and the result was
  dereferenced. It now throws PEMException naming the file. PEMException was already declared in the
  method's throws clause and javadoc.
- EncryptedPrivateKeyReader#getKeyPair(File, String) leaked a file descriptor for every malformed
  PEM file (issue #7). The parser was closed with a plain call after readObject(), so a body that
  makes readObject() throw never reached the close and the underlying FileReader stayed open until
  the garbage collector reclaimed it - a caller validating a batch of key files leaked one
  descriptor per rejected file. It now uses try-with-resources, matching PemObjectReader, which was
  already the only other PEM parser site in this library and already did so. The regression test
  counts the /proc/self/fd entries pointing at the parsed file and skips itself where that
  directory does not exist.


Version 11.2
-------------

CHANGED:

- module-info.java exports the io.github.astrapi69.crypt.data.key package. Cut from the release/11.2
  branch as 11.1 plus only this export, so JPMS consumers could pick it up without waiting for the
  breaking changes queued for 12.0.0.


Version 11.1
-------------

CHANGED:

- build only, no library changes: the signing configuration falls back to the local gpg command
  when no key is in the environment, so a release can be prepared by hand, and the README points
  contributors at the shared testing strategy in mystic-crypt/docs/TESTING.md.


Version 11.0.0
-------------

CHANGED:

- BREAKING: minimum required JDK raised from 21 to 25 (LTS), matching crypt-api 10.0.0 and
  mystic-crypt 11.0.0. Published bytecode now targets JDK 25, so consumers on JDK 21-24 can no
  longer load this artifact - hence the major version bump. CI's setup-java updated to match.
- requires crypt-api 10.0.0 (itself JDK 25; no API changes)
- Maven Central publishing switched from AUTOMATIC to USER_MANAGED: CI uploads and validates the
  deployment, release to Central is approved manually in the Central Portal.
- test quality: line coverage 90.7% -> 99.05%, branch coverage 71.0% -> 98.28%, PIT mutation
  score 87% -> 98% (785/797 mutants killed, test strength 99%); every remaining uncovered line and
  surviving mutant has a stated reason. PIT now also emits mutations.xml. The shared testing
  strategy is documented in mystic-crypt/docs/TESTING.md.

FIXED:

- KeyPairInfo#isValid(KeyPairInfo) rejected every correctly-named registered algorithm: the
  registered-KeyPairGenerator check was inverted, so "RSA"/2048 and "EC"/256 were reported
  invalid while unknown or mis-cased names fell through into key-size probing and escaped as an
  InvocationTargetException (which the old KeyPairInfoTest had enshrined as expected). Unknown
  names now simply return false.
- Pkcs11FactoryTest skipped incorrectly: its guard used new File(configPath).exists(), which is
  true for the empty string Gradle forwards when PKCS11_TEST_CONFIG is unset, so the tests ran
  against an empty path and failed instead of skipping. The guard now requires a non-blank path
  that isFile().

Version 10.3
-------------

ADDED:

- new class KemFactory for generic key encapsulation, wrapping the JDK-standard
  javax.crypto.KEM API (JDK 21+); used for ML-KEM (post-quantum key exchange)
- new class Pkcs11Factory for configuring the JDK's built-in SunPKCS11 provider against a
  PKCS#11 module (HSM, smart card, or software token) and opening its keystore; verified
  end-to-end against a real SoftHSM2 test token (provider config, keystore open, on-token EC
  keypair generation, sign/verify)

CHANGED:

- fixed SignatureFactory#verify to return false instead of throwing SignatureException for
  malformed/tampered signature bytes that fail to decode to a valid point
- updated dependencies to their latest available versions (bcpkix/bcprov 1.85, commons-*,
  file-worker 19.0, guava, junit-jupiter/junit-platform-launcher 6.1.3, lombok, mockito,
  randomizer, silly-*, plus several Gradle plugins); pinned jacoco to 0.8.15
- fixed module-info.java for silly-strings/file-worker's renamed JPMS modules and removed the
  now-unused org.checkerframework.checker.qual requirement (guava 33.7.1-jre dropped that
  dependency in favor of jspecify)
- updated FileInfo/FileCreationState imports to their new package following the file-worker
  19.0 move
- added PIT mutation testing (opt-in, run via `./gradlew pitest`), not wired into check/build

Version 10.2
-------------

ADDED:

- new class HkdfExtensions for HKDF (RFC 5869) key derivation, e.g. to properly derive a
  symmetric key from a raw X25519/ECDH shared secret instead of using it directly
- new class SignatureFactory for generic sign/verify with any java.security.Signature
  algorithm (e.g. Ed25519, natively supported by the JDK since JDK 15)
- new class KeyWrapFactory for AES Key Wrap (RFC 3394): wrap/unwrap a key with another key,
  with an implicit integrity check on unwrap. Natively supported by the JDK (SunJCE), no
  Bouncy Castle needed.
- new class ShamirSecretSharingFactory for Shamir's Secret Sharing: split a secret (e.g. a
  symmetric key) into n shares of which any threshold shares reconstruct it, backed by
  Bouncy Castle's org.bouncycastle.crypto.threshold.ShamirSecretSplitter. Note the total
  share count must not exceed the secret length in bytes (a constraint of the underlying BC
  implementation), and combining fewer than threshold shares silently yields a wrong secret
  rather than failing (Shamir's scheme has no built-in integrity check)
- new explicit direct dependency on bcprov-jdk18on (was previously only pulled in
  transitively via bcpkix-jdk18on)

CHANGED:

- deprecated CipherFactory#newPBECipher(char[], int, String): this overload silently derives
  the cipher with the fixed, publicly known CompoundAlgorithm.SALT and the weak
  CompoundAlgorithm.ITERATIONCOUNT (19) instead of a caller-chosen salt/iteration count; use
  the 5-arg overload with an explicit, randomly generated salt and a modern iteration count
  instead
- fixed SignatureFactory#verify to return false instead of throwing SignatureException for
  malformed/tampered signature bytes that fail to decode to a valid point (JDK's Ed25519
  verifier throws in that case rather than just returning false)
- updated dependencies to their latest available versions: bcpkix-jdk18on/bcprov-jdk18on 1.85,
  commons-codec 1.22.1, commons-csv 1.14.1, commons-io 2.22.0, commons-lang3 3.20.0,
  file-worker 19.0, guava 33.7.1-jre, jobj-core 9.1, jsoup 1.23.1, junit-jupiter/
  junit-platform-launcher 6.1.3, lombok 1.18.46, mockito-core 5.23.0, randomizer 10.3,
  silly-collection 28.1, silly-io 3.6, silly-strings 9.2, plus the grgit, lombok and
  version-catalog-update Gradle plugins; pinned jacoco to 0.8.15
- fixed module-info.java: silly-strings/file-worker module names changed with their version
  bumps (now io.github.astrapisixtynine.silly.strings / io.github.astrapisixtynine.file.worker),
  and the now-unused org.checkerframework.checker.qual requirement was removed since guava
  33.7.1-jre no longer depends on checker-qual (it uses jspecify instead)
- updated FileInfo/FileCreationState imports to their new location
  (io.github.astrapi69.file.create.model) following the file-worker 19.0 package move

Version 10.1
-------------

ADDED:

- new test dependency csv-worker in version 1.0

CHANGED:

- update gradle to new version 8.10.2
- update of dependency commons-io dependency version to 2.17.0
- update of dependency file-worker to new version to 17.3
- update of dependency guava version to new version 33.3.1-jre
- update of test dependency junit-jupiter in version 5.11.1
- update of test dependency junit-platform-launcher in version 1.11.1
- upgrade Bouncy Castle from bcpkix-jdk15on 1.70 (EOL) to bcpkix-jdk18on 1.80, fixing known BC
  CVEs (e.g. CVE-2024-29857)
- enabled the -Xlint:deprecation and -Xlint:unchecked compiler flags
- upgrade gradle wrapper to new version 9.7.0
- bumped GitHub Actions to current major versions (checkout@v7, setup-java@v5,
  setup-gradle@v6, codecov-action@v7) to drop the Node.js 20 deprecation warning

FIXED:

- broadened exception handling in KeySizeExtensions to catch RuntimeException instead of only
  InvalidParameterException; BC 1.80's ML-KEM and composite-signature algorithms reject
  plain int-based initialization via UnsupportedOperationException/IllegalArgumentException,
  which the narrower catch let propagate

Version 10
-------------

CHANGED:

- update to jdk version 21

Version 9.7
-------------

ADDED:

- new class SignatureAlgorithmResolver that resolves all valid signature algorithms for corresponding key pair
  algorithm
- new method in class AlgorithmExtensions that retrieves all appropriate algorithms from a given service name
- new validation method in class KeyPairInfo for validation of KeyPair creation
- new method in class AlgorithmExtensions that retrieves all appropriate algorithms from a given service name with the
  corresponding possible key sizes

CHANGED:

- update of gradle-plugin with id 'com.diffplug.spotless' to new beta version 7.0.0.BETA2
- update of dependency commons-lang3 dependency version to 3.17.0
- update of test dependency jobj-core to new major version 9
- update of test dependency mockito-core to new version to 5.13.0
- update of test dependency mockito-junit-jupiter to new version to 5.13.0

Version 9.6
-------------

ADDED:

- new data info class CertificateInfo
- new test dependency mockito-junit-jupiter
- new factory method in class CertFactory with the new data info class CertificateInfo

CHANGED:

- update gradle to new version 8.10
- update gradle plugin with id 'io.freefair.lombok' to new version 8.10
- improved factory method in class KeyPairFactory#newKeyPair(KeyPairInfo)
- update of dependency commons-lang3 dependency version to 3.16.0
- update of dependency file-worker to new version to 17.3
- update of test dependency junit-jupiter in version 5.11.0
- update of test dependency checksum-up to new version 3.1

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
- update of test dependency junit-jupiter in version 5.11.0-RC1

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
- update of dependency crypt-api to the new minor version 9.2
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
- improve gradle build performance by adding new gradle parameters for caching, parallel, configure on demand and file
  watch

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
