export class NotSupportedError extends Error {}
NotSupportedError.prototype.name = 'NotSupportedError';

export class InvalidAccessError extends Error {}
InvalidAccessError.prototype.name = 'InvalidAccessError';

export class OperationError extends Error {}
OperationError.prototype.name = 'OperationError';

export class QuotaExceededError extends Error {}
QuotaExceededError.prototype.name = 'QuotaExceededError';
