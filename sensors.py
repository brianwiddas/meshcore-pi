
import asyncio

# Default sensors (don't really sense anything)

class HardwarePlatform:
    def __init__(self):
        pass

    def batterymillivolts(self):
        # There is no battery, make up a number
        return 0xffff
