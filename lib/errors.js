'use strict';

class NotSupportedError extends Error {}
NotSupportedError.prototype.name = 'NotSupportedError';

class InvalidAccessError extends Error {}
InvalidAccessError.prototype.name = 'InvalidAccessError';

class OperationError extends Error {}
OperationError.prototype.name = 'OperationError';

class QuotaExceededError extends Error {}
QuotaExceededError.prototype.name = 'QuotaExceededError';

class DataError extends Error {}
DataError.prototype.name = 'DataError';

class TypeMismatchError extends Error {}
TypeMismatchError.prototype.name = 'TypeMismatchError';

module.exports = {
  NotSupportedError,
  InvalidAccessError,
  OperationError,
  QuotaExceededError,
  DataError,
  TypeMismatchError
};
