# import pytest
from ida_domain_mcp.ida_tools import open_database, close_database, get_metadata

def test_db():
    db = open_database("/home/mimi/windev-fuzz/drivers10.0.22631.2861/ntoskrnl.exe")
    close_database(db)

test_db()
