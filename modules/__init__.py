"""
Modules package for Vuln_Scanner_AG.
This init handles dynamic loading of available scanning modules.
"""
import pkgutil
import importlib
import inspect
from utils.logger import logger

def get_available_modules() -> dict:
    """
    Dynamically discover all scanner modules residing in the current package.
    Expects each module to expose a 'run(target: str) -> dict' function.

    Returns:
        dict: A mapping of module name strings to their callable 'run' functions.
    """
    plugins = {}
    package_name = __name__

    try:

        for _, module_name, is_package in pkgutil.iter_modules(__path__):
            if not is_package:
                full_module_name = f"{package_name}.{module_name}"
                try:
                    module_obj = importlib.import_module(full_module_name)


                    if hasattr(module_obj, 'execute') and inspect.isfunction(module_obj.execute):
                        plugins[module_name] = module_obj.execute
                        logger.debug(f"Successfully loaded module: '{module_name}'")
                    else:
                        logger.warning(
                            f"Module '{module_name}' ignored (missing 'execute' function)."
                        )
                except Exception as e:
                    logger.error(f"Failed to dynamically load '{module_name}': {e}")
    except Exception as e:
        logger.error(f"Error during module discovery: {e}")

    return plugins
