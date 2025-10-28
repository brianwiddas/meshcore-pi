
import tomllib

from copy import copy

# Configuration


# This class deals with configuration. It is intended to allow config to be stored in files or elsewhere,
# as well as having the option to provide config as a JSON object, and for a module to have its own default
# configuration. There is also the option to write config (eg, received from the companion app or as CLI
# requests), but it's not currently used.
# It's probably more complicated than it needs to be.
#
# The default config file is called config.toml

class ConfigNotFound(Exception):
    pass


"""
Config - base class
ConfigView - view into a section of the config, eg ("interface")

FileConfig(Config) - load config from a file
SQLiteConfig(Config) - load config from a SQLite database
etc
"""

class ConfigBase:
    def __init__(self, config_data, readonly=False):
        """
        Initialize the ConfigBase object with a dictionary of configuration data.
        """
        self._config_data = config_data
        self.readonly = readonly

    def get(self, key, default=None):
        """
        Retrieve a value from the configuration data using dot notation.
        """
        if key is None or key == '':
            return self._config_data

        keys = key.split('.')
        value = self._config_data

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key, value):
        """
        Put a value into the configuration data using dot notation.

        Returns True if the value was changed.
        """
        if self.readonly:
            return False

        if key is None or key == '':
            raise ValueError("Key cannot be empty")

        keys = key.split('.')

        data = self._config_data

        for k in keys[:-1]:
            data = data.get(k, {})
            if not isinstance(data, dict):
                raise ValueError(f"Cannot set key '{key}': '{k}' is not a dict")

        d = data.get(keys[-1], None)

        if isinstance(d, dict):
            raise ValueError(f"Cannot set key '{key}': '{keys[-1]}' is a dict")

        if d == value:
            # No change
            return False

        data[keys[-1]] = value
        return True

    def __repr__(self):
        return f"ConfigBase({self._config_data}{', readonly' if self.readonly else ''})"

class LocalConfig(ConfigBase):
    def __init__(self):
        # An empty config
        super().__init__({})

    def set(self, key, value):
        return super().set(key, value)


class FileConfig(ConfigBase):
    def __init__(self, file):
        with open(file, "rb") as f:
            self._config_data = tomllib.load(f)
            self.readonly = True

    def set(self, key, value):
        # Cannot set values in a file config
        return False

class ConfigView:
    "A view of the config which refers to the entire configuration, so that changes to the config are reflected in the view"
    def __init__(self, config, section, default=None):
        self._config_list = [(config,section)]

        self._default = (default, '')

    def add_config(self, config, section=''):
        self._config_list.append((config, section))

    def set_default(self, config, section=''):
        self._default = (config, section)

    def get(self, name, default=None, error=False, view=False):
        """
        Retrieve a value from the config view, using dots to separate elements
        If not found, return 'default' unless error is True, then raise an exception.
        If view is True, and the result not found, return a ConfigView object anyway; this allows
        a default to be attached to a config section that doesn't exist.
        """

        # Work backwards through the config list, so that later configs override earlier ones,
        # ending with the default config if present
        for configobj, section in reversed(([self._default] if self._default else []) + self._config_list):
            if configobj is None:
                continue

            full_name = f"{section}.{name}" if section else name
            result =  configobj.get(full_name, default)

            if result is not None:
                break

        if isinstance(result, dict) or (result is None and view):
            # Shallow copy this object, modify it and return it
            new_configview = copy(self)

            # Add the section name to each config in the list
            new_configview._config_list = [
                (config, f"{section}.{name}" if section else name) for config, section in self._config_list]

            # Modify the default to include the section name
            if self._default is not None:
                configobj,section = self._default
                new_configview._default = (configobj, f"{section}.{name}" if section else name)

            return new_configview

        if result is None and error:
            raise ConfigNotFound(f"Config item '{name}' not found")

        if result is None:
            result = default

        return result

    def __repr__(self):
        section = self._config_list[0][1]

        if section is None or section == '':
            return f"ConfigView()"

        return f"ConfigView(section={section})"


default_config = None

def set_default_config(config):
    """
    Set the default config object
    """
    global default_config
    default_config = config

def get_config(item=None):
    """
    Return a config object
    If item is None, return the default config
    If item is a string, load the config from the specified file
    If item is a dict, load the config from the dict
    """

    global default_config

    if item is None:
        if default_config is None:
            set_default_config(FileConfig("config.toml"))

        return ConfigView(default_config, None, None)

    if isinstance(item, str):
        return ConfigView(FileConfig(item), None, None)

    if isinstance(item, dict):
        return ConfigView(ConfigBase(item), None, None)

    raise ValueError("Invalid config item type")