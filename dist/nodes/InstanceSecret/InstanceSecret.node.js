"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InstanceSecret = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const crypto_1 = require("crypto");
class InstanceSecret {
    constructor() {
        this.description = {
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
    }
    async execute() {
        const items = this.getInputData();
        const returnData = [];
        const encryptionKey = process.env.N8N_ENCRYPTION_KEY;
        if (!encryptionKey) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'N8N_ENCRYPTION_KEY environment variable is not set');
        }
        const key = Buffer.from(encryptionKey.padEnd(32, '0').slice(0, 32));
        for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
            try {
                const operation = this.getNodeParameter('operation', itemIndex);
                const inputField = this.getNodeParameter('inputField', itemIndex);
                const outputFieldName = this.getNodeParameter('outputFieldName', itemIndex);
                const options = this.getNodeParameter('options', itemIndex, {});
                const keepOriginal = options.keepOriginal !== false;
                const outputFormat = options.outputFormat || 'hex';
                let result;
                if (operation === 'encrypt') {
                    const iv = (0, crypto_1.randomBytes)(16);
                    const cipher = (0, crypto_1.createCipheriv)('aes-256-cbc', key, iv);
                    let encrypted;
                    let ivString;
                    if (outputFormat === 'base64url') {
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
                    }
                    else {
                        encrypted = cipher.update(inputField, 'utf8', outputFormat);
                        encrypted += cipher.final(outputFormat);
                        ivString = iv.toString(outputFormat);
                    }
                    result = `${ivString}.${encrypted}`;
                }
                else if (operation === 'decrypt') {
                    if (!inputField.includes('.')) {
                        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid encrypted text format. Expected format: iv.encryptedData', { itemIndex });
                    }
                    const parts = inputField.split('.');
                    if (parts.length !== 2) {
                        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid encrypted text format. Expected format: iv.encryptedData', { itemIndex });
                    }
                    const [ivString, encryptedData] = parts;
                    let encoding = 'hex';
                    let isBase64Url = false;
                    if (ivString.length === 32 && /^[0-9a-fA-F]+$/.test(ivString)) {
                        encoding = 'hex';
                    }
                    else if ((ivString.length === 24 || ivString.length === 22) && /[+/=]/.test(ivString)) {
                        encoding = 'base64';
                    }
                    else if (ivString.length === 22 && /^[A-Za-z0-9_-]+$/.test(ivString)) {
                        isBase64Url = true;
                        encoding = 'base64';
                    }
                    else {
                        throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Unable to detect encoding format. IV length: ${ivString.length}. Expected 32 (hex), 24 (base64), or 22 (base64url)`, { itemIndex });
                    }
                    try {
                        let iv;
                        let encryptedBuffer;
                        if (isBase64Url) {
                            const ivBase64 = ivString.replace(/-/g, '+').replace(/_/g, '/');
                            const encryptedBase64 = encryptedData.replace(/-/g, '+').replace(/_/g, '/');
                            iv = Buffer.from(ivBase64, 'base64');
                            encryptedBuffer = Buffer.from(encryptedBase64, 'base64');
                        }
                        else {
                            iv = Buffer.from(ivString, encoding);
                            encryptedBuffer = Buffer.from(encryptedData, encoding);
                        }
                        const decipher = (0, crypto_1.createDecipheriv)('aes-256-cbc', key, iv);
                        let decrypted = decipher.update(encryptedBuffer, undefined, 'utf8');
                        decrypted += decipher.final('utf8');
                        result = decrypted;
                    }
                    catch (error) {
                        throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Decryption failed: ${error.message}`, { itemIndex });
                    }
                }
                else {
                    throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Unknown operation: ${operation}`, { itemIndex });
                }
                const outputItem = {
                    json: keepOriginal ? { ...items[itemIndex].json } : {},
                    pairedItem: itemIndex,
                };
                outputItem.json[outputFieldName] = result;
                returnData.push(outputItem);
            }
            catch (error) {
                if (this.continueOnFail()) {
                    returnData.push({
                        json: {
                            error: error.message,
                        },
                        pairedItem: itemIndex,
                    });
                }
                else {
                    if (error.context) {
                        error.context.itemIndex = itemIndex;
                        throw error;
                    }
                    throw new n8n_workflow_1.NodeOperationError(this.getNode(), error, {
                        itemIndex,
                    });
                }
            }
        }
        return [returnData];
    }
}
exports.InstanceSecret = InstanceSecret;
//# sourceMappingURL=InstanceSecret.node.js.map