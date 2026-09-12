import { z } from 'zod';
import { BoundedResponseError, readBoundedResponseText } from './bounded-response.ts';

export const APPLE_CREDENTIAL_REVIEW_REQUEST_MAXIMUM_BYTES = 2_000;

const opaqueTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const markedAtSchema = z.number().int().nonnegative().max(8_640_000_000_000);

export const appleCredentialReviewResponseSchema = z.discriminatedUnion('manualReviewRequired', [
  z.object({
    manualReviewRequired: z.literal(true),
    acknowledgementId: opaqueTokenSchema,
    markedAt: markedAtSchema,
  }).strict(),
  z.object({
    manualReviewRequired: z.literal(false),
    acknowledgementId: z.null(),
    markedAt: z.null(),
  }).strict(),
]);

export const appleCredentialReviewAcknowledgementRequestSchema = z.object({
  acknowledgementId: opaqueTokenSchema,
}).strict();

export const appleCredentialReviewAcknowledgementResponseSchema = z.object({
  acknowledged: z.literal(true),
}).strict();

export class AppleCredentialReviewRequestError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'AppleCredentialReviewRequestError';
    this.status = status;
    this.code = code;
  }
}

export async function readAppleCredentialReviewAcknowledgementRequest(
  request: Request,
): Promise<z.infer<typeof appleCredentialReviewAcknowledgementRequestSchema>> {
  const mediaType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (mediaType !== 'application/json') {
    throw invalidRequest(
      415,
      'APPLE_AUTH_REQUEST_CONTENT_TYPE',
      'Apple credential review requires an application/json request.',
    );
  }
  const headers = new Headers();
  const declared = request.headers.get('content-length');
  if (declared !== null) headers.set('Content-Length', declared);
  let text: string;
  try {
    text = await readBoundedResponseText(
      new Response(request.body, {headers}),
      APPLE_CREDENTIAL_REVIEW_REQUEST_MAXIMUM_BYTES,
    );
  } catch (error) {
    if (!(error instanceof BoundedResponseError)) throw error;
    if (error.kind === 'too-large') {
      throw invalidRequest(413, 'APPLE_AUTH_REQUEST_TOO_LARGE', 'Apple credential review request is too large.');
    }
    if (error.kind === 'invalid-length') {
      throw invalidRequest(400, 'APPLE_AUTH_REQUEST_CONTENT_LENGTH', 'Apple credential review request has an invalid Content-Length.');
    }
    throw invalidRequest(400, 'APPLE_AUTH_REQUEST_ENCODING', 'Apple credential review request must use valid UTF-8.');
  }
  let decoded: unknown;
  try { decoded = JSON.parse(text); }
  catch { throw invalidRequest(400, 'APPLE_AUTH_REQUEST_INVALID', 'Apple credential review request is invalid.'); }
  const input = appleCredentialReviewAcknowledgementRequestSchema.safeParse(decoded);
  if (!input.success) {
    throw invalidRequest(400, 'APPLE_AUTH_REQUEST_INVALID', 'Apple credential review request is invalid.');
  }
  return input.data;
}

function invalidRequest(status: number, code: string, message: string): AppleCredentialReviewRequestError {
  return new AppleCredentialReviewRequestError(status, code, message);
}
