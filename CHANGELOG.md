## Change log
----------------------

Version 7.7-SNAPSHOT
-------------

Version 7.6
-------------

ADDED:

- new factory class CryptModelFactory for generate objects from class CryptModel
- new factory method in CryptModel with generic key argument
- new delegator methods for PublicKey in PublicKeyExtensions
- new delegator methods for PrivateKey in PrivateKeyExtensions
- new method that can get the private key from an password encrypted byte array
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
