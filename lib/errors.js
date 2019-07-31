'use strict';

class NotSupportedError extends Error {}
NotSupportedError.prototype.name = 'NotSupportedError';

class InvalidAccessError extends Error {}
InvalidAccessError.prototype.name = 'InvalidAccessError';

class OperationError extends Error {}
OperationError.prototype.name = 'OperationError';

class QuotaExceededError extends Error {}
QuotaExceededError.prototype.name = 'QuotaExceededError';

module.exports = {
  NotSupportedError,
  InvalidAccessError,
  OperationError,
  QuotaExceededError
};
