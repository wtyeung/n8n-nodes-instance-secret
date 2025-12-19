import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

export class InstanceSecret implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Instance Secret',
		name: 'instanceSecret',
		icon: 'file:lock.svg',
		group: ['transform'],
		version: 1,
		usableAsTool: true,
		description: 'Encrypt and decrypt data using the instance encryption key',
		defaults: {
			name: 'Instance Secret',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Encrypt',
						value: 'encrypt',
						description: 'Encrypt a string using AES-256-CBC',
						action: 'Encrypt a string',
					},
					{
						name: 'Decrypt',
						value: 'decrypt',
						description: 'Decrypt a string using AES-256-CBC',
						action: 'Decrypt a string',
					},
				],
				default: 'encrypt',
			},
			{
				displayName: 'Input Field',
				name: 'inputField',
				type: 'string',
				default: '',
				required: true,
				description: 'The string to encrypt or decrypt',
				placeholder: 'Enter text to encrypt/decrypt',
			},
			{
				displayName: 'Output Field Name',
				name: 'outputFieldName',
				type: 'string',
				default: 'result',
				required: true,
				description: 'The field name where the result will be stored',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Keep Original',
						name: 'keepOriginal',
						type: 'boolean',
						default: true,
						description: 'Whether to keep the original fields in the output',
					},
					{
						displayName: 'Output Format',
						name: 'outputFormat',
						type: 'options',
						displayOptions: {
							show: {
								'/operation': ['encrypt'],
							},
						},
						options: [
							{
								name: 'Hex',
								value: 'hex',
							},
							{
								name: 'Base64',
								value: 'base64',
							},
							{
								name: 'Base64URL',
								value: 'base64url',
							},
						],
						default: 'hex',
						description: 'The encoding format for encrypted output',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		// Get the encryption key from environment variable
		// eslint-disable-next-line @n8n/community-nodes/no-restricted-globals
		const encryptionKey = process.env.N8N_ENCRYPTION_KEY;

		if (!encryptionKey) {
			throw new NodeOperationError(
				this.getNode(),
				'N8N_ENCRYPTION_KEY environment variable is not set',
			);
		}

		// Ensure the key is 32 bytes for AES-256
		const key = Buffer.from(encryptionKey.padEnd(32, '0').slice(0, 32));

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const operation = this.getNodeParameter('operation', itemIndex) as string;
				const inputField = this.getNodeParameter('inputField', itemIndex) as string;
				const outputFieldName = this.getNodeParameter('outputFieldName', itemIndex) as string;
				const options = this.getNodeParameter('options', itemIndex, {}) as {
					keepOriginal?: boolean;
					outputFormat?: string;
				};

				const keepOriginal = options.keepOriginal !== false;
				const outputFormat = options.outputFormat || 'hex';

				let result: string;

				if (operation === 'encrypt') {
					// Generate a random IV (16 bytes for AES)
					const iv = randomBytes(16);

					// Create cipher
					const cipher = createCipheriv('aes-256-cbc', key, iv);

					// Encrypt the data
					let encrypted: string;
					let ivString: string;

					if (outputFormat === 'base64url') {
						// For base64url, use base64 then convert
						const encryptedBuffer = Buffer.concat([
							cipher.update(inputField, 'utf8'),
							cipher.final(),
						]);
						encrypted = encryptedBuffer
							.toString('base64')
							.replace(/\+/g, '-')
							.replace(/\//g, '_')
							.replace(/=/g, '');
						ivString = iv
							.toString('base64')
							.replace(/\+/g, '-')
							.replace(/\//g, '_')
							.replace(/=/g, '');
					} else {
						encrypted = cipher.update(inputField, 'utf8', outputFormat as BufferEncoding);
						encrypted += cipher.final(outputFormat as BufferEncoding);
						ivString = iv.toString(outputFormat as BufferEncoding);
					}

					// Store IV with encrypted data (format: iv.encryptedData)
					result = `${ivString}.${encrypted}`;
				} else if (operation === 'decrypt') {
					// Validate encrypted text format
					if (!inputField.includes('.')) {
						throw new NodeOperationError(
							this.getNode(),
							'Invalid encrypted text format. Expected format: iv.encryptedData',
							{ itemIndex },
						);
					}

					// Split IV and encrypted data
					const parts = inputField.split('.');
					if (parts.length !== 2) {
						throw new NodeOperationError(
							this.getNode(),
							'Invalid encrypted text format. Expected format: iv.encryptedData',
							{ itemIndex },
						);
					}

					const [ivString, encryptedData] = parts;

					// Detect encoding format based on IV length and character set
					// For 16-byte IV: hex=32 chars, base64=24 chars (with padding), base64url=22 chars
					let encoding: BufferEncoding = 'hex';
					let isBase64Url = false;

					if (ivString.length === 32 && /^[0-9a-fA-F]+$/.test(ivString)) {
						// Hex: 32 characters, only 0-9a-fA-F
						encoding = 'hex';
					} else if ((ivString.length === 24 || ivString.length === 22) && /[+/=]/.test(ivString)) {
						// Standard base64: 22-24 characters with +, /, or =
						encoding = 'base64';
					} else if (ivString.length === 22 && /^[A-Za-z0-9_-]+$/.test(ivString)) {
						// Base64URL: 22 characters, no padding, only A-Za-z0-9_-
						isBase64Url = true;
						encoding = 'base64';
					} else {
						throw new NodeOperationError(
							this.getNode(),
							`Unable to detect encoding format. IV length: ${ivString.length}. Expected 32 (hex), 24 (base64), or 22 (base64url)`,
							{ itemIndex },
						);
					}

					try {
						// Convert IV back to buffer
						let iv: Buffer;
						let encryptedBuffer: Buffer;

						if (isBase64Url) {
							// Convert base64url to base64
							const ivBase64 = ivString.replace(/-/g, '+').replace(/_/g, '/');
							const encryptedBase64 = encryptedData.replace(/-/g, '+').replace(/_/g, '/');
							iv = Buffer.from(ivBase64, 'base64');
							encryptedBuffer = Buffer.from(encryptedBase64, 'base64');
						} else {
							iv = Buffer.from(ivString, encoding);
							encryptedBuffer = Buffer.from(encryptedData, encoding);
						}

						// Create decipher
						const decipher = createDecipheriv('aes-256-cbc', key, iv);

						// Decrypt the data
						let decrypted = decipher.update(encryptedBuffer, undefined, 'utf8');
						decrypted += decipher.final('utf8');

						result = decrypted;
					} catch (error) {
						throw new NodeOperationError(
							this.getNode(),
							`Decryption failed: ${error.message}`,
							{ itemIndex },
						);
					}
				} else {
					throw new NodeOperationError(
						this.getNode(),
						`Unknown operation: ${operation}`,
						{ itemIndex },
					);
				}

				// Prepare output item
				const outputItem: INodeExecutionData = {
					json: keepOriginal ? { ...items[itemIndex].json } : {},
					pairedItem: itemIndex,
				};

				// Add result to output
				outputItem.json[outputFieldName] = result;

				returnData.push(outputItem);
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error.message,
						},
						pairedItem: itemIndex,
					});
				} else {
					if (error.context) {
						error.context.itemIndex = itemIndex;
						throw error;
					}
					throw new NodeOperationError(this.getNode(), error, {
						itemIndex,
					});
				}
			}
		}

		return [returnData];
	}
}
