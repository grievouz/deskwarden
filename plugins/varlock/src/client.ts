import { createHmac } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';

// Client for Deskwarden's secrets socket. The protocol is documented in the
// repo README; the server is Sources/DeskwardenKit/SecretsSocket.

export const DEFAULT_SOCKET_PATH = join(homedir(), '.deskwarden', 'secrets.sock');

const AUTH_CONTEXT = Buffer.from('deskwarden-auth-v1');
const MAX_FRAME_SIZE = 1 << 20;
const HANDSHAKE_TIMEOUT_MS = 10_000;

export type ErrorCode =
  | 'bad_request'
  | 'unauthorized'
  | 'locked'
  | 'denied'
  | 'not_found'
  | 'ambiguous'
  | 'field_not_found'
  | 'unavailable';

export class DeskwardenError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = 'DeskwardenError';
    this.code = code;
  }
}

/** Splits a `dwk_<id>_<secret>` application key into its TLS PSK identity and secret. */
export function parseKey(key: string): { id: string; secret: Buffer } {
  const match = /^dwk_([0-9a-f]+)_([A-Za-z0-9_-]+)$/.exec(key.trim());
  const secret = match ? Buffer.from(match[2], 'base64url') : undefined;
  if (!match || secret?.length !== 32) {
    throw new DeskwardenError('unauthorized', 'That is not a Deskwarden key');
  }
  return { id: match[1], secret };
}

export interface ClientOptions {
  key: string;
  socketPath?: string;
  /** Shown in the Touch ID prompt. */
  clientName?: string;
}

type ServerMessage =
  | { type: 'challenge'; version: number; nonce: string }
  | { type: 'ready' }
  | { type: 'value'; id: string; value: string }
  | { type: 'error'; id?: string; code: ErrorCode; message: string };

interface Pending {
  resolve: (value: string) => void;
  reject: (error: Error) => void;
}

/**
 * One connection to Deskwarden, opened on the first `get` and shared by the
 * rest. It only keeps the process alive while a request is in flight.
 */
export class DeskwardenClient {
  readonly #key: string;
  readonly #socketPath: string;
  readonly #clientName: string;
  #socket?: tls.TLSSocket;
  #ready?: Promise<void>;
  #buffer = Buffer.alloc(0);
  #pending = new Map<string, Pending>();
  #nextId = 1;

  constructor(options: ClientOptions) {
    this.#key = options.key;
    this.#socketPath = options.socketPath ?? DEFAULT_SOCKET_PATH;
    this.#clientName = options.clientName ?? 'varlock';
  }

  async get(path: string, field = 'password'): Promise<string> {
    await this.#connect();
    const id = String(this.#nextId++);
    return new Promise<string>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#updateRef();
      this.#send({ type: 'get', id, path, field });
    });
  }

  close(): void {
    this.#socket?.destroy();
  }

  #connect(): Promise<void> {
    this.#ready ??= new Promise<void>((resolve, reject) => {
      const { id, secret } = parseKey(this.#key);
      let settled = false;
      const fail = (error: Error) => {
        clearTimeout(timeout);
        if (!settled) {
          settled = true;
          reject(error);
        }
        for (const pending of this.#pending.values()) pending.reject(error);
        this.#pending.clear();
        this.#socket?.destroy();
      };
      const timeout = setTimeout(
        () => fail(new DeskwardenError('unavailable', 'Timed out connecting to Deskwarden')),
        HANDSHAKE_TIMEOUT_MS,
      );

      const socket = tls.connect({
        path: this.#socketPath,
        ciphers: 'ECDHE-PSK-CHACHA20-POLY1305',
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.2',
        pskCallback: () => ({ psk: secret, identity: id }),
        // PSK suites have no certificate; the shared key authenticates the server.
        checkServerIdentity: () => undefined,
      });
      this.#socket = socket;

      socket.on('data', (chunk: Buffer) => {
        this.#buffer = Buffer.concat([this.#buffer, chunk]);
        while (this.#buffer.length >= 4) {
          const size = this.#buffer.readUInt32BE(0);
          if (size > MAX_FRAME_SIZE) return fail(new DeskwardenError('bad_request', 'Deskwarden sent an oversized frame'));
          if (this.#buffer.length < 4 + size) break;
          const frame = this.#buffer.subarray(4, 4 + size);
          this.#buffer = this.#buffer.subarray(4 + size);
          handle(JSON.parse(frame.toString('utf8')) as ServerMessage);
        }
      });

      const handle = (message: ServerMessage) => {
        switch (message.type) {
          case 'challenge': {
            const proof = createHmac('sha256', secret)
              .update(AUTH_CONTEXT)
              .update(Buffer.from(message.nonce, 'base64'))
              .digest('base64');
            this.#send({
              type: 'auth',
              keyId: id,
              proof,
              client: { name: this.#clientName, pid: process.pid, cwd: process.cwd() },
            });
            break;
          }
          case 'ready':
            clearTimeout(timeout);
            settled = true;
            resolve();
            this.#updateRef();
            break;
          case 'value':
            this.#settle(message.id, (pending) => pending.resolve(message.value));
            break;
          case 'error':
            if (message.id) {
              this.#settle(message.id, (pending) => pending.reject(new DeskwardenError(message.code, message.message)));
            } else {
              fail(new DeskwardenError(message.code, message.message));
            }
            break;
        }
      };

      socket.on('error', (error: NodeJS.ErrnoException) => fail(connectionError(error)));
      socket.on('close', () => {
        fail(new DeskwardenError('unavailable', 'Deskwarden closed the connection'));
        // The next `get` reconnects.
        if (this.#socket === socket) {
          this.#socket = undefined;
          this.#ready = undefined;
          this.#buffer = Buffer.alloc(0);
        }
      });
    });
    return this.#ready;
  }

  #settle(id: string, finish: (pending: Pending) => void) {
    const pending = this.#pending.get(id);
    if (!pending) return;
    this.#pending.delete(id);
    finish(pending);
    this.#updateRef();
  }

  #send(message: object) {
    const payload = Buffer.from(JSON.stringify(message), 'utf8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length);
    this.#socket?.write(Buffer.concat([header, payload]));
  }

  #updateRef() {
    if (this.#pending.size > 0) this.#socket?.ref();
    else this.#socket?.unref();
  }
}

function connectionError(error: NodeJS.ErrnoException): DeskwardenError {
  switch (error.code) {
    case 'ENOENT':
    case 'ECONNREFUSED':
      return new DeskwardenError('unavailable', "Deskwarden isn't running, or its secrets socket is turned off");
    case 'ERR_SSL_TLSV1_ALERT_UNKNOWN_PSK_IDENTITY':
      return new DeskwardenError('unauthorized', 'Deskwarden does not know this key; the application may have been removed');
    case 'ERR_SSL_SSL/TLS_ALERT_BAD_RECORD_MAC':
      return new DeskwardenError('unauthorized', 'This key does not match the one in Deskwarden');
    default:
      return new DeskwardenError('unavailable', `Could not connect to Deskwarden: ${error.message}`);
  }
}
