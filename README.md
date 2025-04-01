# Lightweight Multi-User Public-Key Authenticated  Encryption With Keyword Search

## Abstract

 Data confidentiality, a fundamental security element for dependable cloud storage, has been drawing widespread concern. Public-key encryption with keyword search (PEKS) has emerged as a promising approach for privacy protection while enabling efficient retrieval of encrypted data. One of the typical applications of PEKS is searching sensitive electronic medical records (EMR) in healthcare clouds. However, many traditional countermeasures fall short of balancing privacy protection with search efficiency, and they often fail to support multiuser EMR sharing. To resolve these challenges, we propose a novel lightweight multi-user public-key authenticated encryption scheme with keyword search (LM-PAEKS). Our design effectively counters the inside keyword guessing attack (IKGA) while maintaining the sizes of ciphertext and trapdoor constant in multi-user scenarios. The novelty of our approach relies on introducing a dedicated receiver server that skillfully transforms the complex many-to-many relationship between senders and receivers into a streamlined one-to-one relationship. This transformation prevents the sizes of ciphertext and trapdoor from scaling linearly with the number of participants. Our approach ensures ciphertext indistinguishability and trapdoor privacy while avoiding bilinear pairing operations on the client side. Comparative performance analysis demonstrates that LM-PAEKS features significant computational efficiency while meeting higher security requirements, positioning it as a robust alternative to existing solutions.

## Requirements

 The project is intended to run on Ubuntu 24.04 using Python 3.9. The following Python packages are required:

- Charm-Crypto (https://github.com/JHUISI/charm)
