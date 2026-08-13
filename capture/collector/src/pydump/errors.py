class PydumpError(Exception):
    """A capture failure with enough context to report directly to the operator."""


class ProtocolError(PydumpError):
    """The Collector and Agent disagreed on their session protocol."""
