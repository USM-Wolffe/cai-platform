"""Small core error model for orchestration-neutral coordination logic."""


class CoreError(Exception):
    """Base error for platform-core."""


class NotFoundError(CoreError):
    """Raised when a required contract object cannot be found."""


class InvalidStateError(CoreError):
    """Raised when a contract object is in a state that blocks the requested action."""


class UnsupportedBackendError(CoreError):
    """Raised when a backend does not support a required workflow or capability."""


class ApprovalRequiredError(CoreError):
    """Raised when policy requires approval and no acceptable approval is present."""


class ContractViolationError(CoreError):
    """Raised when an operation would violate the shared contract shape."""
