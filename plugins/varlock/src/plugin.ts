import { homedir } from 'node:os';
import { join } from 'node:path';
import { type Resolver, plugin } from 'varlock/plugin-lib';
import { DEFAULT_SOCKET_PATH, DeskwardenClient, DeskwardenError } from './client.ts';

const { SchemaError, ResolutionError, ValidationError } = plugin.ERRORS;

plugin.name = 'deskwarden';
const { debug } = plugin;

const KEY_TIP = 'Add an application in Deskwarden → Settings → External Applications, then pass its key with @initDeskwarden(key=$DESKWARDEN_KEY)';

class DeskwardenInstance {
  keyResolver?: Resolver;
  socketPath = DEFAULT_SOCKET_PATH;
  #client?: DeskwardenClient;

  async get(path: string, field: string): Promise<string> {
    try {
      return await (await this.#getClient()).get(path, field);
    } catch (error) {
      throw toResolutionError(error, path);
    }
  }

  async #getClient(): Promise<DeskwardenClient> {
    if (this.#client) return this.#client;
    const key = await this.keyResolver?.resolve();
    if (typeof key !== 'string' || !key) {
      throw new ResolutionError('The Deskwarden key is empty', { tip: KEY_TIP });
    }
    debug('connecting to', this.socketPath);
    this.#client = new DeskwardenClient({ key, socketPath: this.socketPath, clientName: 'varlock' });
    return this.#client;
  }
}

function toResolutionError(error: unknown, path: string) {
  if (!(error instanceof DeskwardenError)) {
    return error instanceof Error ? error : new ResolutionError(String(error));
  }
  const tips: Partial<Record<DeskwardenError['code'], string>> = {
    unavailable: 'Start Deskwarden and make sure Secrets Socket is checked in its menu',
    unauthorized: KEY_TIP,
    locked: 'Unlock your vault from the Deskwarden menu bar icon',
    denied: 'Approve the Touch ID prompt from Deskwarden',
    not_found: 'Paths are "Folder/Item name", or just "Item name" when it is unique; an item id also works',
    ambiguous: 'Add the folder ("Folder/Item name") or use the item id',
  };
  return new ResolutionError(`${error.message} (${path})`, { tip: tips[error.code] });
}

function expandHome(path: string): string {
  if (path === '~') return homedir();
  if (path.startsWith('~/')) return join(homedir(), path.slice(2));
  return path;
}

const instances: Record<string, DeskwardenInstance> = {};

plugin.registerRootDecorator({
  name: 'initDeskwarden',
  description: 'Connect to the Deskwarden menu bar app for deskwarden() resolvers',
  isFunction: true,
  async process(argsVal) {
    const objArgs = argsVal.objArgs ?? {};

    if (objArgs.id && !objArgs.id.isStatic) {
      throw new SchemaError('Expected id to be static');
    }
    const id = String(objArgs.id?.staticValue || '_default');
    if (instances[id]) {
      throw new SchemaError(`Deskwarden instance with id "${id}" already initialized`);
    }
    if (!objArgs.key) {
      throw new SchemaError('@initDeskwarden needs a key', { tip: KEY_TIP });
    }
    if (objArgs.socketPath && !objArgs.socketPath.isStatic) {
      throw new SchemaError('Expected socketPath to be static');
    }

    instances[id] = new DeskwardenInstance();
    return {
      id,
      keyResolver: objArgs.key,
      socketPath: objArgs.socketPath ? expandHome(String(objArgs.socketPath.staticValue)) : undefined,
    };
  },
  async execute({ id, keyResolver, socketPath }) {
    const instance = instances[id];
    instance.keyResolver = keyResolver;
    if (socketPath) instance.socketPath = socketPath;
  },
});

plugin.registerDataType({
  name: 'deskwardenKey',
  sensitive: true,
  typeDescription: 'Deskwarden application key (dwk_…), from Deskwarden → Settings → External Applications',
  async validate(value) {
    if (typeof value !== 'string' || !value.startsWith('dwk_')) {
      throw new ValidationError('Deskwarden keys start with "dwk_"');
    }
  },
});

plugin.registerResolverFunction({
  name: 'deskwarden',
  label: 'Fetch a field from a Bitwarden vault item through Deskwarden',
  argsSchema: {
    type: 'mixed',
    arrayMinLength: 1,
    arrayMaxLength: 2,
  },
  process() {
    let instanceId = '_default';
    let pathResolver: Resolver;
    const fieldResolver = this.objArgs?.field;

    const arrArgs = this.arrArgs ?? [];
    if (arrArgs.length === 1) {
      pathResolver = arrArgs[0];
    } else if (arrArgs.length === 2) {
      if (!arrArgs[0].isStatic) {
        throw new SchemaError('Expected instance id (first argument) to be a static value');
      }
      instanceId = String(arrArgs[0].staticValue);
      pathResolver = arrArgs[1];
    } else {
      throw new SchemaError('Expected deskwarden("Folder/Item") or deskwarden(instanceId, "Folder/Item")');
    }

    if (!instances[instanceId]) {
      throw new SchemaError(
        instanceId === '_default'
          ? 'No Deskwarden instance found'
          : `Deskwarden instance id "${instanceId}" not found`,
        { tip: `Initialize it with @initDeskwarden(${instanceId === '_default' ? '' : `id=${instanceId}, `}key=$DESKWARDEN_KEY)` },
      );
    }

    return { instanceId, pathResolver, fieldResolver };
  },
  async resolve({ instanceId, pathResolver, fieldResolver }) {
    const path = await pathResolver.resolve();
    if (typeof path !== 'string' || !path) {
      throw new SchemaError('Expected the item path to resolve to a non-empty string');
    }
    let field = 'password';
    if (fieldResolver) {
      const resolved = await fieldResolver.resolve();
      if (typeof resolved === 'string' && resolved) field = resolved;
    }
    return await instances[instanceId].get(path, field);
  },
});
