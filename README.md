# n8n-nodes-instance-secret

This is an n8n community node that lets you encrypt and decrypt sensitive data using your n8n instance's encryption key.

The Instance Secret node provides secure encryption and decryption capabilities using AES-256-CBC encryption algorithm, leveraging the same encryption key that n8n uses internally (N8N_ENCRYPTION_KEY environment variable).

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/sustainable-use-license/) workflow automation platform.

[Installation](#installation) • [Operations](#operations) • [Configuration](#configuration) • [Usage](#usage) • [Resources](#resources)

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

### Manual Installation

```bash
npm install n8n-nodes-instance-secret
```

## Operations

The Instance Secret node supports two operations:

### Encrypt
Encrypts a string using AES-256-CBC encryption algorithm. The encrypted output includes the initialization vector (IV) in the format `iv.encryptedData`.

### Decrypt
Decrypts a previously encrypted string. Expects input in the format `iv.encryptedData`.

## Configuration

### Parameters

- **Operation**: Choose between Encrypt or Decrypt
- **Input Field**: The string to encrypt or decrypt
- **Output Field Name**: The field name where the result will be stored (default: "result")

### Options

- **Keep Original**: Whether to keep the original fields in the output (default: true)
- **Output Format** (Encrypt only): Choose between hex, base64, or base64url encoding (default: hex)

## Usage

### Prerequisites

The node requires the `N8N_ENCRYPTION_KEY` environment variable to be set. This is the same encryption key used by n8n for storing credentials.

### Example: Encrypting Data

1. Add the Instance Secret node to your workflow
2. Select "Encrypt" operation
3. Enter the text you want to encrypt in the "Input Field"
4. Choose your preferred output format (hex or base64)
5. The encrypted result will be stored in the specified output field

### Example: Decrypting Data

1. Add the Instance Secret node to your workflow
2. Select "Decrypt" operation
3. Provide the encrypted text (in `iv.encryptedData` format) in the "Input Field"
4. The decrypted result will be stored in the specified output field

### Error Handling

The node supports n8n's `continueOnFail` mode. When enabled, errors will be captured in the output instead of stopping the workflow.

Common errors:
- Missing `N8N_ENCRYPTION_KEY` environment variable
- Invalid encrypted text format for decryption
- Decryption failures (wrong key, corrupted data)

## Compatibility

- Minimum n8n version: 1.0.0
- Tested with n8n version: 1.x

## Resources

* [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
* [n8n encryption documentation](https://docs.n8n.io/)

## License

MIT

## Version History

### 0.1.0
- Initial release
- Encrypt and decrypt operations
- AES-256-CBC encryption
- Support for hex, base64, and base64url output formats
