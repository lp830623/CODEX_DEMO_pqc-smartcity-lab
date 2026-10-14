"""Expected failures for the CityLink lab protocol."""


class CityLinkError(Exception):
    """Base class for failures a peer should log and reject."""


class ProtocolError(CityLinkError):
    """The bytes are not a well-formed CityLink message."""


class AuthenticationError(CityLinkError):
    """A signature or AEAD tag check failed."""


class ReplayError(CityLinkError):
    """A client nonce or telemetry sequence number was reused."""


class PolicyError(CityLinkError):
    """The peer offered a suite, profile, or flag this side will not accept."""


class CryptoError(CityLinkError):
    """A primitive rejected a key or a ciphertext."""
