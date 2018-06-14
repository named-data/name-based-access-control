NAC Specification
=================

.. figure:: _static/nac-overview.png
   :alt: Overview of NAC entities
   :align: center

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
----------------

The ``EncryptedContent`` element contains encrypted blob, optional Initial Vector (for AES CBC encryption),
optional EncryptedPayloadKey, and Name elements.

::

     EncryptedContent ::= ENCRYPTED-CONTENT-TYPE TLV-LENGTH
                            EncryptedPayload
                            InitialVector?
                            EncryptedPayloadKey?
                            Name?

     InitialVector ::= INITIAL-VECTOR-TYPE TLV-LENGTH(=N) BYTE{N}
     EncryptedPayload ::= ENCRYPTED-PAYLOAD-TYPE TLV-LENGTH(=N) BYTE{N}
     EncryptedPayloadKey ::= ENCRYPTED-PAYLOAD-KEY-TYPE TLV-LENGTH(=N) BYTE{N}
     InitialVector ::= INITIAL-VECTOR-TYPE TLV-LENGTH(=N) BYTE{N}


Access Manager
--------------

.. figure:: _static/access-manager.png
   :alt: Access Manager
   :align: center

Access Manager controls decryption policy by publishing granular per-namespace access policies in the form of key encryption (KEK, plaintext public) and key decryption (KDK, encrypted private keys) key pairs.

KEK is published as a single data packet with name ``/[access-namespace]/NAC/[dataset]/KEK/[key-id]``, following the following format:

::

   Kek ::= DATA-TYPE TLV-LENGTH
             Name (= /[access-namespace]/NAC/[dataset]/KEK/[key-id])
             MetaInfo (= .ContentType = KEY, .FreshnessPeriod = 1 hour)
             KekContent
             SignatureInfo
             SignatureValue

   KekContent ::= CONTENT-TYPE-TLV TLV-LENGTH
                    BYTE* (= BER of public key /[access-namespace]/NAC/[dataset]/KEY/[key-id])


Different versions of KDK are published, encrypted by the public key of the individual authorized member, following naming convention: ``/[access-namespace]/NAC/[dataset]/KDK/[key-id]/ENCRYPTED-BY/<authorized-member>/KEY/[member-key-id]``.  KDK is published in the following format:

::

   Kdk ::= DATA-TYPE TLV-LENGTH
             Name (= /[access-namespace]/NAC/[dataset]/KDK/[key-id]/ENCRYPTED-BY/<authorized-member>/KEY/[member-key-id])
             MetaInfo (= .ContentType = KEY, .FreshnessPeriod = 1 hour)
             KdkContent
             SignatureInfo
             SignatureValue

   KdkContent ::= CONTENT-TYPE-TLV TLV-LENGTH
                    EncryptedContent (=
                      .EncryptedPayload = SafeBag with private key /[access-namespace]/NAC/[dataset]/KEY/[key-id]
                      .EncryptedPayloadKey = password for SafeBag, encrypted by public key /<authorized-member>/KEY/[member-key-id]
                      // .InitialVector and .Name not set
                    )
