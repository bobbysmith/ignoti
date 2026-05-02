/**
 * @file validation.ts
 * Validation utilities for API client
 */

import { VALIDATION } from '@/constants';
import { ErrorCodes, GhostIDError } from '../core/errors';

/**
 * Validates a string input with length constraints
 * @param value - String value to validate
 * @param fieldName - Name of the field for error messages
 * @param maxLength - Maximum allowed length
 * @returns Trimmed string if valid
 * @throws GhostIDError if validation fails
 */
export function validateString(
  value: unknown,
  fieldName: string,
  maxLength: number = VALIDATION.MAX_STRING_LENGTH
): string {
  if (!value || typeof value !== 'string') {
    throw new GhostIDError(`Invalid ${fieldName} provided`, ErrorCodes.INVALID_INPUT);
  }

  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw new GhostIDError(`${fieldName} cannot be empty`, ErrorCodes.INVALID_INPUT);
  }

  if (trimmed.length > maxLength) {
    throw new GhostIDError(
      `${fieldName} exceeds maximum length of ${maxLength}`,
      ErrorCodes.INVALID_INPUT
    );
  }

  return trimmed;
}
