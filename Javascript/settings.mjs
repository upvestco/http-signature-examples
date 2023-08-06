import 'dotenv/config';
import { env } from 'node:process';

export const PRIVATE_KEY_FILE = env.PRIVATE_KEY_FILE;
export const PRIVATE_KEY_PASSWORD = env.PRIVATE_KEY_PASSWORD;
export const SERVER_BASE_URL = env.SERVER_BASE_URL;
export const KEY_ID = env.KEY_ID;
export const CLIENT_ID = env.CLIENT_ID;
export const CLIENT_SECRET = env.CLIENT_SECRET;
export const SCOPES = env.SCOPES.split(',');

export default {
    PRIVATE_KEY_FILE,
    PRIVATE_KEY_PASSWORD,
    SERVER_BASE_URL,
    KEY_ID,
    CLIENT_ID,
    CLIENT_SECRET,
    SCOPES,
}
