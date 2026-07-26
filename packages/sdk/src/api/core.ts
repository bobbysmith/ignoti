/**
 * Core API client. Validates inputs at the type/format level (URL, header
 * grammar, body size) without applying HTML/SQL escaping. This is an HTTP
 * client not an HTML/SQL renderer, so context-mismatched escaping would
 * corrupt our payloads.
 */

import { SERVER_ERROR_CODES, type ServerErrorResponse } from '@ghostid/shared';
import {
  API_ENDPOINTS,
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

/** The bound `CoreApiClient.makeRequest`, injected into each API module. */
export type MakeRequest = <T>(
  method: string,
  path: string,
  data?: Record<string, unknown> | string | number | boolean,
  headers?: Record<string, string>
) => Promise<T>;

export class CoreApiClient {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly retryAttempts: number;
  private readonly onUnauthorized?: (
    method: string,
    path: string
  ) => Promise<Record<string, string>>;

  /**
   * A 401 means "stale session, restore and re-sign" only on routes that
   * authenticate via session headers. Everywhere else (login, restore,
   * register/device, root-JWS device revoke) a 401 is a terminal verification
   * failure. Intercepting it would mask the real error with a pointless
   * restore attempt and burn the restore-failure budget.
   */
  private static isSessionAuthedPath(path: string): boolean {
    return (
      path === API_ENDPOINTS.DEVICES.LIST ||
      path === API_ENDPOINTS.SESSIONS.LIST ||
      path.startsWith(`${API_ENDPOINTS.SESSIONS.REVOKE}/`)
    );
  }

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
    this.onUnauthorized = options.onUnauthorized;
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
    return this.executeRequest<T>(method, path, data, headers, true);
  }

  private async executeRequest<T>(
    method: string,
    path: string,
    data: Record<string, unknown> | string | number | boolean | undefined,
    headers: Record<string, string>,
    allowUnauthorizedRetry: boolean
  ): Promise<T> {
    this.validateHttpMethod(method);
    const validatedPath = this.validatePath(path);
    const validatedHeaders = this.validateHeaders(headers);

    const url = `${this.baseUrl}${validatedPath}`;
    const requestHeaders: Record<string, string> = { ...validatedHeaders };

    const requestOptions: RequestInit = {
      method,
      headers: requestHeaders,
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

    for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
      const outcome = await this.attemptRequest<T>(url, requestOptions);

      if (outcome.kind === 'value') {
        return outcome.value;
      }

      // 401 on a session-authed route: restore the session and re-sign, then
      // retry once. Any other 401 is terminal.
      if (outcome.kind === 'unauthorized') {
        if (
          allowUnauthorizedRetry &&
          this.onUnauthorized &&
          CoreApiClient.isSessionAuthedPath(validatedPath)
        ) {
          const freshHeaders = await this.onUnauthorized(method, validatedPath);
          return this.executeRequest<T>(method, path, data, freshHeaders, false);
        }
        throw outcome.error;
      }

      lastError = outcome.error;
      if (attempt < this.retryAttempts) {
        await retryDelay(attempt);
      }
    }

    throw new GhostIDError(
      `${ERROR_MESSAGES.API_REQUEST_FAILED}: ${lastError?.message}`,
      ErrorCodes.API_ERROR,
      lastError
    );
  }

  /**
   * One request attempt with its own timeout, so each retry gets the full
   * budget and the backoff sleeps between attempts are not counted against it.
   * Returns a value or a retryable failure, or a 401 for the caller to decide
   * whether to intercept; throws terminal errors (timeout, 4xx/501, clock
   * skew, unparseable body).
   */
  private async attemptRequest<T>(
    url: string,
    requestOptions: RequestInit
  ): Promise<
    | { kind: 'value'; value: T }
    | { kind: 'unauthorized'; error: GhostIDError }
    | { kind: 'retry'; error: Error }
  > {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    try {
      let response: Response;
      try {
        response = await fetch(url, { ...requestOptions, signal: controller.signal });
      } catch (fetchError) {
        const err = fetchError instanceof Error ? fetchError : new Error(String(fetchError));
        if (err.name === 'AbortError') {
          throw new GhostIDError(ERROR_MESSAGES.REQUEST_TIMED_OUT, ErrorCodes.API_ERROR, err);
        }
        // Browsers surface every network failure as TypeError - transient
        // (offline, DNS, reset) and permanent (CORS, bad config) alike, and are
        // indistinguishable here, so both are retried by the caller.
        return { kind: 'retry', error: err };
      }

      if (!response.ok) {
        const errorData = await this.parseErrorResponse(response);

        // A skewed device clock fails the server's signature timestamp check;
        // restoring the session re-signs with the same clock, so don't retry.
        if (
          response.status === HTTP_STATUS.UNAUTHORIZED &&
          errorData.error === SERVER_ERROR_CODES.SESSION_TIMESTAMP_OUT_OF_RANGE
        ) {
          throw new GhostIDError(
            ERROR_MESSAGES.CLOCK_SKEW,
            ErrorCodes.CLOCK_SKEW,
            new Error(`HTTP ${response.status}`),
            response.status
          );
        }

        const message = this.capErrorMessage(
          errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`
        );
        const ghostError = new GhostIDError(
          message,
          ErrorCodes.API_ERROR,
          new Error(`HTTP ${response.status}`),
          response.status
        );

        if (ghostError.httpStatus === HTTP_STATUS.UNAUTHORIZED) {
          return { kind: 'unauthorized', error: ghostError };
        }

        // 4xx (not handled above) and 501: retrying won't change the outcome.
        if (
          (ghostError.httpStatus &&
            ghostError.httpStatus >= HTTP_STATUS_RANGES.CLIENT_ERROR_START &&
            ghostError.httpStatus <= HTTP_STATUS_RANGES.CLIENT_ERROR_END) ||
          ghostError.httpStatus === HTTP_STATUS.NOT_IMPLEMENTED
        ) {
          throw ghostError;
        }

        return { kind: 'retry', error: ghostError };
      }

      try {
        return { kind: 'value', value: (await response.json()) as T };
      } catch (parseError) {
        throw new GhostIDError(
          ERROR_MESSAGES.FAILED_TO_PARSE_RESPONSE,
          ErrorCodes.API_ERROR,
          parseError
        );
      }
    } finally {
      clearTimeout(timeoutId);
    }
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
