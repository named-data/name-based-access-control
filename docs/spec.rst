NAC Specification
=================

TBD

Terminology
-----------

+-----------------+------------------------------------------------------------------------------------------+
| Term            |  Description                                                                             |
+=================+==========================================================================================+
| KEK             |  Key Encryption Key (RSA public key)                                                     |
+-----------------+------------------------------------------------------------------------------------------+
| KDK             |  Key Decryption Key (RSA private key)                                                    |
+-----------------+------------------------------------------------------------------------------------------+
| CK              |  Content Key (AES symmetric key)                                                         |
+-----------------+------------------------------------------------------------------------------------------+
| CK data         |  Data packet carrying a KDK-encrypted CK as payoad                                       |
+-----------------+------------------------------------------------------------------------------------------+
| Access Manager  |  (Data Owner) Entity that control access to the data associated with the namespace       |
+-----------------+------------------------------------------------------------------------------------------+
| Encryptor       |  (Producer) Entity that encrypts data based on namespace association                     |
+-----------------+------------------------------------------------------------------------------------------+
| Decryptor       |  (Consumer) Entity that decrypts data based on namespace association                     |
+-----------------+------------------------------------------------------------------------------------------+

EncryptedContent
-----------------

The ``EncryptedContent`` element contains encrypted blob, optional Initial Vector (for AES CBC encryption),
optional EncryptedPayloadKey, and Name elements.

::

     EncryptedContent ::= ENCRYPTED-CONTENT-TYPE TLV-LENGTH
                            EncryptedPayload
                            InitialVector
                            EncryptedPayloadKey
                            Name

     InitialVector ::= INITIAL-VECTOR-TYPE TLV-LENGTH(=N) BYTE{N}
     EncryptedPayload ::= ENCRYPTED-PAYLOAD-TYPE TLV-LENGTH(=N) BYTE{N}
     EncryptedPayloadKey ::= ENCRYPTED-PAYLOAD-KEY-TYPE TLV-LENGTH(=N) BYTE{N}
     InitialVector ::= INITIAL-VECTOR-TYPE TLV-LENGTH(=N) BYTE{N}
