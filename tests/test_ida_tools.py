# import pytest
from ida_domain_mcp.ida_tools import open_database, close_database, get_metadata

binary_path = "/home/xy/Projects/CTFAgents/AttackAgent/files/crackme03.elf"

def test_db():
    db = open_database(binary_path)
    print(get_metadata())
    close_database(db)

test_db()
