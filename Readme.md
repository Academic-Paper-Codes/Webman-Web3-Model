# Webman: Decentralized Framework for Web 3.0 Model Management

Official Java implementation of **Webman**, a decentralized framework for hierarchical Web 3.0 model lifecycle management presented in the IEEE Transactions on Mobile Computing 2026 paper: *"Return Rights to Mobile Users: A Decentralized Framework for Web 3.0 Model Management"*.

## Overview

Webman addresses the critical challenge of model-stealing attacks in Web 3.0 by cryptographically enforcing owner-defined hierarchical policies over AI model usage, training, and upgrading. Unlike traditional centralized approaches, Webman ensures that all participating entities—including decentralized servers—are bound to comply with model management rights.

### Key Features

- **Hierarchical Access Control**: Three-tier downward-compatible management rights (availability, trainability, upgradability)
- **Model-Stealing Resistance**: Cryptographic enforcement prevents unauthorized model access and replication
- **Blockchain Integration**: Immutable audit trail using chameleon hash-based redactable mechanisms
- Two Deployment Modes:
  - **Semi-Webman**: Limited owner involvement during model inference
  - **Full-Webman**: Fully autonomous operation via multi-server collaboration

## Architecture

The Webman framework consists of five key participants:

1. **Web 3.0 Curator**: Manages user registration and public key aggregation without holding secret information
2. **Model Owner**: Trains AI models, defines management policies, and uploads encrypted models
3. **Web 3.0 Servers**: Store encrypted models and perform privacy-preserving computations
4. **Blockchain**: Stores model metadata, ownership information, and access control policies
5. **Web 3.0 Users**: Access models according to hierarchical permissions (availability, trainability, upgradability)

## Implementation Structure

### Core Components

#### 1. `WebmanUtils.java`

Utility classes providing foundational data structures:

- **SystemParameters**: Manages bilinear group parameters, maximum users (N), users per block (n), and block count (B)
- **PublicParameters**: Maintains aggregated public keys for each block
- **AuxiliaryParameters**: Stores auxiliary information for user decryption
- **UserKeys**: Encapsulates user secret keys, public keys, and personal auxiliary parameters
- **ProcessedModel**: Contains encrypted model data with associated policies and cryptographic keys
- **RightsParameters**: Holds access parameters for availability, trainability, and upgradability rights

#### 2. `SemiWebman.java`

Implements the Semi-Webman variant requiring limited owner participation:

**Key Algorithms**:

- `setup(λ, N, n)`: Initializes system with security parameter λ, maximum users N, and block size n

- `keyGen(uid)`: Generates user keys using Registration-Based Encryption (RBE)

- `register(userKeys)`: Verifies and registers users with the Web 3.0 curator

- ```
  process(policyA, policyT, policyU, model)
  ```

  : Encrypts model with hierarchical policies using:

  - Paillier homomorphic encryption for availability
  - AES symmetric encryption for trainability
  - Chameleon hash for upgradability

- `check(uid, processedModel)`: Verifies user rights and returns appropriate parameters

- `update(uid, k)`: Retrieves auxiliary parameters for decryption

- `avail(skid, Lid, Ra, m)`: Performs model inference with owner-assisted decryption

- `train(skid, Lid, Rt)`: Enables authorized users to train models locally

- `upgrade(skid, Lid, Ru, trainedModels)`: Aggregates trained models and updates the master model

#### 3. `FullWebman.java`

Extends Semi-Webman to eliminate owner participation through multi-server collaboration:

**Additional Features**:

- **Homomorphic Key Splitting**: Distributes Paillier private key across multiple servers using Shamir Secret Sharing
- **Collaborative Decryption**: Servers jointly decrypt inference results using threshold cryptography
- **ServerShare Class**: Manages distributed key shares with server identifiers
- **DistributedProcessedModel**: Extended processed model containing server share information

**Key Differences from Semi-Webman**:

- `process()`: Splits homomorphic secret key `ska` into `ns` shares distributed to servers
- `avail()`: Servers collaboratively decrypt without owner involvement using Lagrange interpolation
- `upgrade()`: Generates new key shares when updating models

## Dependencies

This implementation requires:

- **Java 8+**

- **JPBC (Java Pairing-Based Cryptography)**: For bilinear pairing operations

- **Paillier Homomorphic Encryption Library**: For encrypted computation

- **AES Encryption**: For symmetric operations

- Custom Cryptographic Primitives

  :

  - `crypto.BilinearGroup`
  - `crypto.PaillierEncryption`
  - `crypto.AESEncryption`
  - `crypto.ChameleonHash`
  - `crypto.HomomorphicMLPEvaluator`
  - `crypto.ShamirSecretSharing`
  - `crypto.Model`

## File Structure

```
webman/
├── WebmanUtils.java          # Core data structures and utilities
├── SemiWebman.java           # Semi-delegated implementation
└── FullWebman.java           # Fully-delegated multi-server implementation
```

## License

Please refer to the paper and contact the authors for licensing information.

## Future Work

- Accountability and revocability mechanisms
- Post-quantum secure constructions
- Policy confidentiality protection
- Medical AI model applications

## Contact

For questions or collaboration opportunities, please contact:

- Zekai Yu: zekaiy@bit.edu.cn

------

**Note**: This implementation is for research purposes. The cryptographic libraries in the `crypto` package are not included in this repository and must be implemented separately according to the specifications in the paper.