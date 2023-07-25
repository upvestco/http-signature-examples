import { readFile } from 'node:fs/promises';
import { createPrivateKey } from 'node:crypto';

export class NodeKeyLoader {
    async readKeyFile(fileName) {
        try {
            return await readFile(fileName);
        } catch (err) {
            console.error(err.message);
        }
    }

    async load(keyFileName, keyPassword) {
        return createPrivateKey({
            key: await this.readKeyFile(keyFileName),
            format: 'pem',
            passphrase: keyPassword,
        })
    }
}
