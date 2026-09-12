import {
  OriginAuthError,
  type OriginConfiguration,
  type OriginInstallationReceipt,
  type OriginReceiptVerificationDependencies,
  createOriginInstallationStart,
  verifyOriginInstallationReceipt,
} from './origin-auth.ts';
import { BoundedResponseError, readBoundedResponseText } from './bounded-response.ts';

export const ORIGIN_FLOW_COOKIE = '__Host-local_sandbox_origin_flow';
export const ORIGIN_COMMAND_MAXIMUM_BYTES = 20_000;

export function originConfigurationForRequest(
  request: Request,
  configuration: OriginConfiguration,
): OriginConfiguration {
  if (new URL(request.url).origin !== new URL(configuration.redirectUri).origin) {
    throw new OriginAuthError(
      503,
      'ORIGIN_CALLBACK_ORIGIN_MISMATCH',
      'This site origin does not match the registered Cursor Origin callback.',
    );
  }
  return configuration;
}

export function originInstallationStartResponse(
  request: Request,
  configuration: OriginConfiguration,
  cryptoProvider: Crypto,
): Response {
  if (request.method !== 'GET') {
    throw new OriginAuthError(405, 'ORIGIN_METHOD_NOT_ALLOWED', 'Cursor Origin installation must start with GET.');
  }
  const url = new URL(request.url);
  if ([...url.searchParams.keys()].length !== 0) {
    throw new OriginAuthError(400, 'ORIGIN_START_INVALID', 'Cursor Origin installation does not accept URL parameters.');
  }
  originConfigurationForRequest(request, configuration);
  const start = createOriginInstallationStart(configuration, cryptoProvider);
  return new Response(null, {
    status: 303,
    headers: {
      'Cache-Control': 'no-store',
      Location: start.authorizationUrl,
      'Set-Cookie': originFlowCookie(start.state),
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function verifyOriginInstallationCallback(input: {
  request: Request;
  dependencies: OriginReceiptVerificationDependencies;
}): Promise<OriginInstallationReceipt> {
  if (input.request.method !== 'GET') {
    throw new OriginAuthError(405, 'ORIGIN_METHOD_NOT_ALLOWED', 'Cursor Origin callbacks must use GET.');
  }
  const url = new URL(input.request.url);
  const values = url.searchParams.getAll('installation_receipt');
  if ([...url.searchParams.keys()].some(key => key !== 'installation_receipt') || values.length !== 1) {
    throw new OriginAuthError(400, 'ORIGIN_CALLBACK_INVALID', 'The Cursor Origin callback is invalid.');
  }
  const serializedReceipt = values[0];
  if (serializedReceipt.length > 20_000) {
    throw new OriginAuthError(413, 'ORIGIN_CALLBACK_TOO_LARGE', 'The Cursor Origin callback is too large.');
  }
  const expectedState = readCookie(input.request, ORIGIN_FLOW_COOKIE);
  if (!expectedState) {
    throw new OriginAuthError(400, 'ORIGIN_INSTALL_STATE_INVALID', 'The Cursor Origin install state is missing or invalid.');
  }
  return verifyOriginInstallationReceipt(input.dependencies, serializedReceipt, expectedState);
}

export async function persistOriginInstallationOrRequireManualCleanup<T>(input: {
  persist(): Promise<T>;
  releaseAuthority?(): Promise<void>;
}): Promise<T> {
  try {
    return await input.persist();
  } catch {
    try {
      await input.releaseAuthority?.();
    } catch {
      // The durable possible-installation marker remains fail-closed if lease cleanup is unavailable.
    }
    throw new OriginAuthError(
      502,
      'ORIGIN_INSTALLATION_COMPENSATION_REQUIRED',
      'Local Sandbox could not confirm that this Cursor Origin installation was saved. Review or remove it in Cursor Origin settings before retrying.',
    );
  }
}

export function originAuthErrorResponse(error: unknown, additionalHeaders?: HeadersInit): Response {
  const known = error instanceof OriginAuthError
    ? error
    : new OriginAuthError(503, 'ORIGIN_AUTH_UNAVAILABLE', 'Cursor Origin authentication could not complete.');
  const headers = new Headers(additionalHeaders);
  headers.set('Cache-Control', 'no-store');
  headers.set('Content-Type', 'application/json');
  headers.set('X-Content-Type-Options', 'nosniff');
  return Response.json({error: known.message, code: known.code}, {status: known.status, headers});
}

export function requireOriginSameOrigin(request: Request): void {
  if (request.headers.get('origin') !== new URL(request.url).origin) {
    throw new OriginAuthError(403, 'ORIGIN_CSRF', 'Submit this action from the Local Sandbox site.');
  }
}

export async function readOriginCommandRequest(request: Request): Promise<unknown> {
  const mediaType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (mediaType !== 'application/json') {
    throw new OriginAuthError(
      415,
      'ORIGIN_REQUEST_CONTENT_TYPE',
      'Cursor Origin commands require an application/json request.',
    );
  }
  const headers = new Headers();
  const declared = request.headers.get('content-length');
  if (declared !== null) headers.set('Content-Length', declared);
  let text: string;
  try {
    text = await readBoundedResponseText(
      new Response(request.body, {headers}),
      ORIGIN_COMMAND_MAXIMUM_BYTES,
    );
  } catch (error) {
    if (!(error instanceof BoundedResponseError)) throw error;
    if (error.kind === 'too-large') {
      throw new OriginAuthError(413, 'ORIGIN_REQUEST_TOO_LARGE', 'Cursor Origin request is too large.');
    }
    if (error.kind === 'invalid-length') {
      throw new OriginAuthError(
        400,
        'ORIGIN_REQUEST_CONTENT_LENGTH',
        'Cursor Origin request has an invalid Content-Length.',
      );
    }
    throw new OriginAuthError(
      400,
      'ORIGIN_REQUEST_ENCODING',
      'Cursor Origin request must use valid UTF-8.',
    );
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new OriginAuthError(400, 'ORIGIN_REQUEST_INVALID', 'Cursor Origin request is invalid.');
  }
}

export function readCookie(request: Request, name: string): string | null {
  const matches = (request.headers.get('cookie') ?? '')
    .split(';')
    .map(part => part.trim())
    .filter(part => part.startsWith(`${name}=`));
  if (matches.length !== 1) return null;
  return matches[0].slice(name.length + 1) || null;
}

export function originFlowCookie(value: string, maxAge = 10 * 60): string {
  return `${ORIGIN_FLOW_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearOriginFlowCookie(): string {
  return originFlowCookie('', 0);
}

export function safeOriginReturnTo(value:string|null):string{
  if(!value||!value.startsWith('/')||value.startsWith('//'))return '/local/index.html';
  try{
    const url=new URL(value,'https://app.local');
    if(url.origin!=='https://app.local'||url.pathname.startsWith('/api/origin'))return '/local/index.html';
    return `${url.pathname}${url.search}${url.hash}`;
  }catch{return '/local/index.html';}
}

export function originResultRedirect(returnTo:string,result:'connected'|'cancelled'):URL{
  const url=new URL(returnTo,'https://app.local');
  url.searchParams.set('cursor_origin',result);
  return url;
}
