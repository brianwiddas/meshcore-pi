
# Exceptions for Meshcore

class InvalidPacket(Exception):
    """Exception raised for invalid packets."""
    pass

class InvalidMeshcorePacket(InvalidPacket):
    """Exception raised for invalid Meshcore packets."""
    pass

class UnknownMeshcoreVersion(InvalidMeshcorePacket):
    """Exception raised for unknown Meshcore version."""
    pass

class UnknownMeshcoreType(InvalidMeshcorePacket):
    """Exception raised for unknown Meshcore type."""
    pass

class UnknownMeshcoreRouting(InvalidMeshcorePacket):
    """Exception raised for unknown Meshcore routing."""
    pass
