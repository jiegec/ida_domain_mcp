# import pytest
import os
from ida_domain_mcp.ida_tools import open_database, close_database, get_metadata

base_dir = os.path.dirname(__file__)
binary_path = os.path.join(base_dir, "binaries", "crackme03.elf")

def test_db():
    db = open_database(binary_path)
    print(get_metadata())
    close_database(db)

test_db()
