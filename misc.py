
# Handy functions that don't really fit anywhere else

import time

_unique_time = 0

def unique_time():
    """
    Return a unique timestamp
    """
    global _unique_time

    t = int(time.time())
    if t <= _unique_time:
        t = _unique_time + 1
    _unique_time = t

    return t


def pathstr(path, flood=False):
    """
    Convenience function to convert a path bytearray/bytes object to a printable string

    None = Flood
    [] = Direct, or 0-hop if flood=True
    [ ... ] = hex path, comma separated
    """
    if path is None:
        return "Flood"
    if len(path) == 0:
        return "0-hop" if flood else "Direct"
    return ",".join( (f"{p:02x}" for p in path) )


def pad(data, length):
    """
    Zero-pad the data to the length specified

    data should be a bytes-like object or str, which will be converted to bytes
    """
    if isinstance(data, str):
        b = data.encode()
    else:
        b = data
    
    l = len(b)
    if l>=length:
        return b
    
    return b + bytes(length - l)

# Break a string up into chunks of max_size bytes, trying to split on word boundaries, and not
# splitting in the middle of a multi-byte UTF-8 character
def split_unicode_string(s, max_size):
    """
    Split a unicode string into utf-8 byte strings, each no longer than max_size.
    Splits on word boundaries where possible.
    """
    if not isinstance(s, str):
        raise ValueError("Input must be a unicode string")

    utf8_bytes = s.encode('utf-8')
    chunks = []
    start = 0

    while start < len(utf8_bytes):
        end = start + max_size
        if end >= len(utf8_bytes):
            chunks.append(utf8_bytes[start:])
            break

        # Adjust the boundary to avoid splitting in the middle of a character
        boundary = end
        while boundary > start and (utf8_bytes[boundary] & 0xC0) == 0x80:
            boundary -= 1

        # Find the last space within the valid boundary
        space_boundary = utf8_bytes[start:boundary].rfind(b' ')
        if space_boundary != -1:
            boundary = start + space_boundary

        chunks.append(utf8_bytes[start:boundary])
        start = boundary + 1  # Move past the space

    return chunks


# Validate a latitude and longitude
# Must be a number between -180 and 180 for lon, and -90 to 90 for lat
# Returns a tuple of (lat, lon) as floats, or raises ValueError
def validate_latlon(lat, lon):
    try:
        lat = float(lat)
        lon = float(lon)
    except ValueError:
        raise ValueError("Latitude and longitude must be numbers")

    if lat < -90 or lat > 90:
        raise ValueError("Latitude must be between -90 and 90")
    if lon < -180 or lon > 180:
        raise ValueError("Longitude must be between -180 and 180")

    return (lat, lon)


# Subclass of list which calls a callback when modified
class CallbackList(list):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._callback = None
        self._callback_args = ()

    def set_callback(self, callback, *args):
        """
        Set the callback function to be called when the list is modified
        The callback function will be called with the list as the first argument,
        followed by any additional args specified here
        """
        self._callback = callback
        self._callback_args = args

    def _trigger_callback(self):
        if self._callback:
            self._callback(self, *self._callback_args)

    def append(self, item):
        super().append(item)
        self._trigger_callback()

    def extend(self, iterable):
        super().extend(iterable)
        self._trigger_callback()

    def insert(self, index, item):
        super().insert(index, item)
        self._trigger_callback()

    def remove(self, item):
        super().remove(item)
        self._trigger_callback()

    def pop(self, index=-1):
        item = super().pop(index)
        self._trigger_callback()
        return item

    def clear(self):
        super().clear()
        self._trigger_callback()

    def __iadd__(self, value):
        newlist = super().__iadd__(value)
        self._trigger_callback()
        return newlist

    def __imul__(self, value):
        newlist = super().__imul__(value)
        self._trigger_callback()
        return newlist

    def __setitem__(self, index, value):
        super().__setitem__(index, value)
        self._trigger_callback()

    def __delitem__(self, index):
        super().__delitem__(index)
        self._trigger_callback()

    def sort(self, *args, **kwargs):
        super().sort(*args, **kwargs)
        self._trigger_callback()

    def reverse(self):
        super().reverse()
        self._trigger_callback()