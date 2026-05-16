/**
 * @file core.ts
 * Core API client. Validates inputs at the type/format level (URL, header
 * grammar, body size) without applying HTML/SQL escaping. This is an HTTP
 * client not an HTML/SQL renderer, so context-mismatched escaping would
 * corrupt our payloads.
 */

import type { ServerErrorResponse } from '@ghostid/shared';
import {
  ERROR_MESSAGES,
  HTTP_HEADERS,
  HTTP_METHODS,
  HTTP_STATUS,
  HTTP_STATUS_RANGES,
  RETRY,
  SECURITY,
  TIMEOUTS,
} from '@/constants';
import type { ApiClientOptions } from '@/types';
import { ErrorCodes, GhostIDError } from '../core/errors';

/** RFC 3986 path subset we accept (alphanum || unreserved || slash). */
const PATH_RE = /^\/[A-Za-z0-9\-._~/]*$/;
/** RFC 7230 token grammar (header name). */
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** RFC 7230 field-value: visible ASCII and tab/space, no CR/LF. */
const HEADER_VALUE_RE = /^[\t\x20-\x7E]*$/;

const FORBIDDEN_REQUEST_HEADERS = new Set<string>(SECURITY.FORBIDDEN_HEADERS);

export class CoreApiClient {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly retryAttempts: number;

  constructor(options: ApiClientOptions) {
    if (!options.baseUrl) {
      throw new GhostIDError(ERROR_MESSAGES.INVALID_BASE_URL, ErrorCodes.INVALID_INPUT);
    }
    let parsed: URL;
    try {
      parsed = new URL(options.baseUrl);
    } catch {
      throw new GhostIDError(ERROR_MESSAGES.INVALID_BASE_URL_FORMAT, ErrorCodes.INVALID_INPUT);
    }
    const isHttps = parsed.protocol === 'https:';
    const isLocalhost =
      parsed.protocol === 'http:' &&
      (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1');
    if (!isHttps && !isLocalhost) {
      throw new GhostIDError(ERROR_MESSAGES.BASE_URL_REQUIRES_HTTPS, ErrorCodes.INVALID_INPUT);
    }
    // Strip trailing slash so `${baseUrl}${path}` always produces one slash.
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.timeout = options.timeout ?? TIMEOUTS.DEFAULT_REQUEST;
    this.retryAttempts = options.retryAttempts ?? RETRY.DEFAULT_ATTEMPTS;
    if (this.timeout <= 0 || this.timeout > 300_000) {
      throw new GhostIDError(ERROR_MESSAGES.INVALID_TIMEOUT, ErrorCodes.INVALID_INPUT);
    }
    if (this.retryAttempts < 1 || this.retryAttempts > 10) {
      throw new GhostIDError(ERROR_MESSAGES.INVALID_RETRY_ATTEMPTS, ErrorCodes.INVALID_INPUT);
    }
  }

  private validateHttpMethod(method: string): void {
    if (
      !SECURITY.ALLOWED_HTTP_METHODS.includes(
        method as (typeof SECURITY.ALLOWED_HTTP_METHODS)[number]
      )
    ) {
      throw new GhostIDError(
        `${ERROR_MESSAGES.INVALID_HTTP_METHOD}: ${method}`,
        ErrorCodes.INVALID_INPUT
      );
    }
  }

  /**
   * Defense-in-depth check on the URL path. Paths come from `API_ENDPOINTS`
   * constants we control - this is a guardrail against accidental misuse.
   */
  private validatePath(path: string): string {
    if (!path) {
      throw new GhostIDError(ERROR_MESSAGES.INVALID_PATH, ErrorCodes.INVALID_INPUT);
    }
    if (path.length > SECURITY.MAX_PATH_LENGTH) {
      throw new GhostIDError(ERROR_MESSAGES.PATH_TOO_LONG, ErrorCodes.INVALID_INPUT);
    }
    if (!PATH_RE.test(path)) {
      throw new GhostIDError(ERROR_MESSAGES.INVALID_PATH_FORMAT, ErrorCodes.INVALID_INPUT);
    }
    return path;
  }

  /**
   * RFC 7230 grammar check (no CR/LF - header injection guard) plus a
   * forbidden-name check. Does not modify values.
   */
  private validateHeaders(headers: Record<string, string>): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
      if (
        name.length === 0 ||
        name.length > SECURITY.MAX_HEADER_NAME_LENGTH ||
        !HEADER_NAME_RE.test(name)
      ) {
        throw new GhostIDError(
          `${ERROR_MESSAGES.INVALID_HEADER_NAME}: ${name}`,
          ErrorCodes.INVALID_INPUT
        );
      }
      const lower = name.toLowerCase();
      if (FORBIDDEN_REQUEST_HEADERS.has(lower)) {
        throw new GhostIDError(
          `${ERROR_MESSAGES.FORBIDDEN_HEADER}: ${name}`,
          ErrorCodes.INVALID_INPUT
        );
      }
      if (value.length > SECURITY.MAX_HEADER_VALUE_LENGTH || !HEADER_VALUE_RE.test(value)) {
        throw new GhostIDError(
          `${ERROR_MESSAGES.INVALID_HEADER_VALUE} ${name}`,
          ErrorCodes.INVALID_INPUT
        );
      }
      out[lower] = value;
    }
    return out;
  }

  /**
   * JSON.stringify with a body-size cap. No content escaping - we ship the
   * payload as-is so signatures verify and binary-safe fields (base64url)
   * survive intact. Circular references are caught natively by JSON.stringify.
   */
  private safeStringify(data: unknown): string {
    let stringified: string;
    try {
      stringified = JSON.stringify(data);
    } catch (error) {
      throw new GhostIDError(
        ERROR_MESSAGES.FAILED_TO_SERIALIZE,
        ErrorCodes.INVALID_INPUT,
        error as Error
      );
    }
    if (stringified.length > SECURITY.MAX_REQUEST_BODY_SIZE) {
      throw new GhostIDError(ERROR_MESSAGES.REQUEST_BODY_TOO_LARGE, ErrorCodes.INVALID_INPUT);
    }
    return stringified;
  }

  /** Truncates long error messages to avoid runaway log lines. */
  private capErrorMessage(message: string): string {
    return message.length > 500 ? `${message.substring(0, 500)}...` : message;
  }

  async makeRequest<T>(
    method: string,
    path: string,
    data?: Record<string, unknown> | string | number | boolean,
    headers: Record<string, string> = {}
  ): Promise<T> {
    this.validateHttpMethod(method);
    const validatedPath = this.validatePath(path);
    const validatedHeaders = this.validateHeaders(headers);

    const url = `${this.baseUrl}${validatedPath}`;
    const requestHeaders: Record<string, string> = { ...validatedHeaders };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    const requestOptions: RequestInit = {
      method,
      headers: requestHeaders,
      signal: controller.signal,
      credentials: 'include',
    };

    if (
      data !== undefined &&
      (method === HTTP_METHODS.POST ||
        method === HTTP_METHODS.PUT ||
        method === HTTP_METHODS.PATCH ||
        method === HTTP_METHODS.DELETE)
    ) {
      requestHeaders[HTTP_HEADERS.CONTENT_TYPE] = HTTP_HEADERS.APPLICATION_JSON;
      requestOptions.body = this.safeStringify(data);
    }
    // POST and PATCH are not idempotent. Retrying them is safe here because
    // every GhostID mutation is guarded server-side by a single-use challenge
    // or a unique constraint, so a duplicate request is rejected, not applied.

    const retryDelay = (attempt: number) =>
      new Promise<void>(resolve =>
        setTimeout(
          resolve,
          Math.min(
            TIMEOUTS.DEFAULT_RETRY_DELAY * RETRY.EXPONENTIAL_BACKOFF_BASE ** (attempt - 1),
            TIMEOUTS.MAX_RETRY_DELAY
          )
        )
      );

    let lastError: Error | null = null;

    try {
      for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
        let response: Response;

        try {
          response = await fetch(url, requestOptions);
        } catch (fetchError) {
          lastError = fetchError instanceof Error ? fetchError : new Error(String(fetchError));
          if (fetchError instanceof Error && fetchError.name === 'AbortError') {
            throw new GhostIDError(
              ERROR_MESSAGES.REQUEST_TIMED_OUT,
              ErrorCodes.API_ERROR,
              fetchError
            );
          }

          if (fetchError instanceof TypeError) {
            throw fetchError;
          }
          if (attempt < this.retryAttempts) {
            await retryDelay(attempt);
          }

          continue;
        }

        if (!response.ok) {
          const errorData = await this.parseErrorResponse(response);
          const message = this.capErrorMessage(
            errorData.error ||
              errorData.message ||
              `HTTP ${response.status}: ${response.statusText}`
          );
          const ghostError = new GhostIDError(
            message,
            ErrorCodes.API_ERROR,
            new Error(`HTTP ${response.status}`),
            response.status
          );
          lastError = ghostError;
          const { httpStatus: status } = ghostError;
          // 4xx: retrying won't change the outcome.
          // 501: server does not implement the endpoint - not transient.
          if (
            (status &&
              status >= HTTP_STATUS_RANGES.CLIENT_ERROR_START &&
              status <= HTTP_STATUS_RANGES.CLIENT_ERROR_END) ||
            status === HTTP_STATUS.NOT_IMPLEMENTED
          ) {
            throw ghostError;
          }

          if (attempt < this.retryAttempts) {
            await retryDelay(attempt);
          }
          continue;
        }

        try {
          return await response.json();
        } catch (parseError) {
          throw new GhostIDError(
            ERROR_MESSAGES.FAILED_TO_PARSE_RESPONSE,
            ErrorCodes.API_ERROR,
            parseError
          );
        }
      }
    } finally {
      clearTimeout(timeoutId);
    }

    throw new GhostIDError(
      `${ERROR_MESSAGES.API_REQUEST_FAILED}: ${lastError?.message}`,
      ErrorCodes.API_ERROR,
      lastError
    );
  }

  private async parseErrorResponse(response: Response): Promise<Partial<ServerErrorResponse>> {
    try {
      const contentType = response.headers.get(HTTP_HEADERS.CONTENT_TYPE);
      if (contentType?.includes(HTTP_HEADERS.APPLICATION_JSON)) {
        return (await response.json()) as Partial<ServerErrorResponse>;
      }
    } catch {
      // Ignore parsing errors
    }
    return { message: response.statusText };
  }
}
