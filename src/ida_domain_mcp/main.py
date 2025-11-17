import argparse
from urllib.parse import urlparse
import json
import traceback
import multiprocessing as mp
from mcp.server.fastmcp import FastMCP
from multiprocessing.connection import Connection
from typing import Dict, Tuple, Any



# project_name -> (Process, parent_conn)
PROJECTS: Dict[str, Tuple[mp.Process, Connection]] = {}


def _worker(conn: Connection):
    """Child process loop hosting an IDA Database via ida_tools."""
    db = None
    try:
        from ida_domain_mcp import ida_tools as tools
    except Exception as e:
        # If ida_tools cannot be imported in child, notify parent and exit
        err = {"ok": False, "error": f"failed to import ida_tools: {e}", "traceback": traceback.format_exc()}
        try:
            conn.send(err)
        except Exception:
            pass
        conn.close()
        return

    while True:
        try:
            msg = conn.recv()
        except EOFError:
            break
        except Exception as e:
            try:
                conn.send({"ok": False, "error": str(e), "traceback": traceback.format_exc()})
            except Exception:
                pass
            break

        if not isinstance(msg, dict):
            try:
                conn.send({"ok": False, "error": "invalid message"})
            except Exception:
                pass
            continue

        mtype = msg.get("type")
        try:
            if mtype == "open":
                db_path = msg["db_path"]
                auto_analysis = msg.get("auto_analysis", True)
                new_database = msg.get("new_database", False)
                save_on_close = msg.get("save_on_close", False)
                db = tools.open_database(
                    db_path,
                    auto_analysis=auto_analysis,
                    new_database=new_database,
                    save_on_close=save_on_close,
                )
                conn.send({"ok": True})
            elif mtype == "call":
                func_name = msg.get("func")
                args = msg.get("args", [])
                kwargs = msg.get("kwargs", {})
                if not func_name or not hasattr(tools, func_name):
                    conn.send({"ok": False, "error": f"unknown function: {func_name}"})
                    continue
                func = getattr(tools, func_name)
                result = func(*args, **kwargs)
                conn.send({"ok": True, "result": result})
            elif mtype == "close":
                save = msg.get("save", None)
                try:
                    tools.close_database(db, save=save)
                finally:
                    db = None
                conn.send({"ok": True})
                break
            else:
                conn.send({"ok": False, "error": f"unknown message type: {mtype}"})
        except Exception as e:
            conn.send({"ok": False, "error": str(e), "traceback": traceback.format_exc()})

    try:
        conn.close()
    except Exception:
        pass

mcp = FastMCP("IDA Domain MCP Server")


def _ensure_project(project_name: str) -> Tuple[mp.Process, Connection]:
    if project_name not in PROJECTS:
        raise ValueError(f"Project '{project_name}' is not open")
    return PROJECTS[project_name]


def _call_project(project_name: str, func: str, *args: Any, **kwargs: Any) -> Any:
    proc, conn = _ensure_project(project_name)
    if not proc.is_alive():
        # cleanup stale mapping
        try:
            conn.close()
        except Exception:
            pass
        del PROJECTS[project_name]
        raise RuntimeError(f"Project '{project_name}' worker not running")

    conn.send({"type": "call", "func": func, "args": list(args), "kwargs": kwargs})
    reply = conn.recv()
    if not isinstance(reply, dict) or not reply.get("ok"):
        raise RuntimeError(f"call {func} failed: {reply.get('error') if isinstance(reply, dict) else reply}")
    return reply.get("result")


@mcp.tool()
async def get_metadata(project_name: str) -> str:
    """Get metadata about the current IDB."""
    result = _call_project(project_name, "get_metadata")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def open_database(
    project_name: str,
    db_path: str,
    auto_analysis: bool = True,
    new_database: bool = False,
    save_on_close: bool = False,
) -> str:
    """Open an IDA Database in a dedicated worker for this project."""
    if project_name in PROJECTS:
        proc, _ = PROJECTS[project_name]
        if proc.is_alive():
            return json.dumps({"status": "already_open"}, ensure_ascii=False)
        # stale; clean up mapping
        try:
            PROJECTS.pop(project_name, None)
        except Exception:
            pass

    parent_conn, child_conn = mp.Pipe()
    proc = mp.Process(target=_worker, args=(child_conn,), daemon=True)
    proc.start()

    # The child sends an error immediately if ida_tools import failed; otherwise wait for open ack
    # Send open request
    parent_conn.send(
        {
            "type": "open",
            "db_path": db_path,
            "auto_analysis": auto_analysis,
            "new_database": new_database,
            "save_on_close": save_on_close,
        }
    )
    reply = parent_conn.recv()
    if not isinstance(reply, dict) or not reply.get("ok"):
        # ensure process is terminated
        try:
            parent_conn.close()
        except Exception:
            pass
        try:
            if proc.is_alive():
                proc.terminate()
        except Exception:
            pass
        err = reply.get("error") if isinstance(reply, dict) else str(reply)
        raise RuntimeError(f"open_database failed: {err}")

    PROJECTS[project_name] = (proc, parent_conn)
    return json.dumps({"status": "opened"}, ensure_ascii=False)


@mcp.tool()
async def get_function_by_name(project_name: str, name: str) -> str:
    """Get a function by its name."""
    result = _call_project(project_name, "get_function_by_name", name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_function_by_address(project_name: str, address: int) -> str:
    """Get a function by its address."""
    result = _call_project(project_name, "get_function_by_address", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def convert_number(project_name: str, text: str, size: int) -> str:
    """Convert a number (decimal, hexadecimal) to different representations."""
    result = _call_project(project_name, "convert_number", text, size)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_functions_filter(
    project_name: str,
    offset: int,
    count: int,
    filter: str,
) -> str:
    """List matching functions in the database (paginated, filtered)."""
    result = _call_project(project_name, "list_functions_filter", offset, count, filter)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_functions(project_name: str, offset: int, count: int) -> str:
    """List all functions in the database (paginated)."""
    result = _call_project(project_name, "list_functions", offset, count)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_globals_filter(
    project_name: str,
    offset: int,
    count: int,
    filter: str,
) -> str:
    """List matching globals in the database (paginated, filtered)."""
    result = _call_project(project_name, "list_globals_filter", offset, count, filter)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_globals(project_name: str, offset: int, count: int) -> str:
    """List all globals in the database (paginated)."""
    result = _call_project(project_name, "list_globals", offset, count)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_imports(project_name: str, offset: int, count: int) -> str:
    """List all imported symbols with their name and module (paginated)."""
    result = _call_project(project_name, "list_imports", offset, count)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_strings_filter(
    project_name: str,
    offset: int,
    count: int,
    filter: str,
) -> str:
    """List matching strings in the database (paginated, filtered)."""
    result = _call_project(project_name, "list_strings_filter", offset, count, filter)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_strings(project_name: str, offset: int, count: int) -> str:
    """List all strings in the database (paginated)."""
    result = _call_project(project_name, "list_strings", offset, count)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_segments(project_name: str) -> str:
    """List all segments in the binary."""
    result = _call_project(project_name, "list_segments")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def list_local_types(project_name: str) -> str:
    """List all Local types in the database."""
    result = _call_project(project_name, "list_local_types")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def decompile_function(project_name: str, address: int) -> str:
    """Decompile a function at the given address."""
    result = _call_project(project_name, "decompile_function", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def disassemble_function(project_name: str, start_address: int) -> str:
    """Get assembly code for a function (API-compatible with older IDA builds)."""
    result = _call_project(project_name, "disassemble_function", hex(start_address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_xrefs_to(project_name: str, address: int) -> str:
    """Get all cross references to the given address."""
    result = _call_project(project_name, "get_xrefs_to", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_xrefs_to_field(
    project_name: str,
    struct_name: str,
    field_name: str,
) -> str:
    """Get all cross references to a named struct field (member)."""
    result = _call_project(project_name, "get_xrefs_to_field", struct_name, field_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_callees(project_name: str, function_address: int) -> str:
    """Get all the functions called by the function at function_address."""
    result = _call_project(project_name, "get_callees", hex(function_address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_callers(project_name: str, function_address: int) -> str:
    """Get all callers of the given address."""
    result = _call_project(project_name, "get_callers", hex(function_address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_entry_points(project_name: str) -> str:
    """Get all entry points in the database."""
    result = _call_project(project_name, "get_entry_points")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_comment(project_name: str, address: int, comment: str) -> str:
    """Set a comment for a given address in the function disassembly and pseudocode."""
    result = _call_project(project_name, "set_comment", hex(address), comment)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def rename_local_variable(
    project_name: str,
    function_address: int,
    old_name: str,
    new_name: str,
) -> str:
    """Rename a local variable in a function."""
    result = _call_project(project_name, "rename_local_variable", hex(function_address), old_name, new_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def rename_global_variable(
    project_name: str,
    old_name: str,
    new_name: str,
) -> str:
    """Rename a global variable."""
    result = _call_project(project_name, "rename_global_variable", old_name, new_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_global_variable_type(
    project_name: str,
    variable_name: str,
    new_type: str,
) -> str:
    """Set a global variable's type."""
    result = _call_project(project_name, "set_global_variable_type", variable_name, new_type)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def patch_address_assembles(
    project_name: str,
    address: int,
    instructions: str,
) -> str:
    """Patch code at the given address with the provided instructions."""
    result = _call_project(project_name, "patch_address_assembles", hex(address), instructions)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_global_variable_value_by_name(
    project_name: str,
    variable_name: str,
) -> str:
    """Read a global variable's value (if known at compile-time)."""
    result = _call_project(project_name, "get_global_variable_value_by_name", variable_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_global_variable_value_at_address(
    project_name: str,
    address: int,
) -> str:
    """Read a global variable's value by its address (if known at compile-time)."""
    result = _call_project(project_name, "get_global_variable_value_at_address", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def rename_function(
    project_name: str,
    function_address: int,
    new_name: str,
) -> str:
    """Rename a function."""
    result = _call_project(project_name, "rename_function", hex(function_address), new_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_function_prototype(
    project_name: str,
    function_address: int,
    prototype: str,
) -> str:
    """Set a function's prototype."""
    result = _call_project(project_name, "set_function_prototype", hex(function_address), prototype)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def declare_c_type(project_name: str, c_declaration: str) -> str:
    """Create or update a local type from a C declaration."""
    result = _call_project(project_name, "declare_c_type", c_declaration)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_local_variable_type(
    project_name: str,
    function_address: int,
    variable_name: str,
    new_type: str,
) -> str:
    """Set a local variable's type."""
    result = _call_project(project_name, "set_local_variable_type", hex(function_address), variable_name, new_type)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_stack_frame_variables(
    project_name: str,
    function_address: int,
) -> str:
    """Retrieve the stack frame variables for a given function."""
    result = _call_project(project_name, "get_stack_frame_variables", hex(function_address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_defined_structures(project_name: str) -> str:
    """Returns a list of all defined structures."""
    result = _call_project(project_name, "get_defined_structures")
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def analyze_struct_detailed(project_name: str, name: str) -> str:
    """Detailed analysis of a structure with all fields."""
    result = _call_project(project_name, "analyze_struct_detailed", name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_struct_at_address(
    project_name: str,
    address: int,
    struct_name: str,
) -> str:
    """Get structure field values at a specific address."""
    result = _call_project(project_name, "get_struct_at_address", hex(address), struct_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def get_struct_info_simple(project_name: str, name: str) -> str:
    """Simple function to get basic structure information."""
    result = _call_project(project_name, "get_struct_info_simple", name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def search_structures(project_name: str, filter: str) -> str:
    """Search for structures by name pattern."""
    result = _call_project(project_name, "search_structures", filter)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def rename_stack_frame_variable(
    project_name: str,
    function_address: int,
    old_name: str,
    new_name: str,
) -> str:
    """Change the name of a stack variable for an IDA function."""
    result = _call_project(project_name, "rename_stack_frame_variable", hex(function_address), old_name, new_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def create_stack_frame_variable(
    project_name: str,
    function_address: int,
    offset: int,
    variable_name: str,
    type_name: str,
) -> str:
    """For a given function, create a stack variable at an offset and with a specific type."""
    result = _call_project(project_name, "create_stack_frame_variable", hex(function_address), hex(offset), variable_name, type_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def set_stack_frame_variable_type(
    project_name: str,
    function_address: int,
    variable_name: str,
    type_name: str,
) -> str:
    """For a given disassembled function, set the type of a stack variable."""
    result = _call_project(project_name, "set_stack_frame_variable_type", hex(function_address), variable_name, type_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def delete_stack_frame_variable(
    project_name: str,
    function_address: int,
    variable_name: str,
) -> str:
    """Delete the named stack variable for a given function."""
    result = _call_project(project_name, "delete_stack_frame_variable", hex(function_address), variable_name)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def read_memory_bytes(
    project_name: str,
    memory_address: int,
    size: int,
) -> str:
    """Read bytes at a given address."""
    result = _call_project(project_name, "read_memory_bytes", hex(memory_address), size)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_byte(project_name: str, address: int) -> str:
    """Read the 1 byte value at the specified address."""
    result = _call_project(project_name, "data_read_byte", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_word(project_name: str, address: int) -> str:
    """Read the 2 byte value at the specified address as a WORD."""
    result = _call_project(project_name, "data_read_word", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_dword(project_name: str, address: int) -> str:
    """Read the 4 byte value at the specified address as a DWORD."""
    result = _call_project(project_name, "data_read_dword", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_qword(project_name: str, address: int) -> str:
    """Read the 8 byte value at the specified address as a QWORD."""
    result = _call_project(project_name, "data_read_qword", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def data_read_string(project_name: str, address: int) -> str:
    """Read the string at the specified address."""
    result = _call_project(project_name, "data_read_string", hex(address))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
async def close_database(project_name: str, save: bool | None = None) -> str:
    """Close the project's IDA Database and shutdown its worker."""
    proc, conn = _ensure_project(project_name)
    if not proc.is_alive():
        try:
            conn.close()
        except Exception:
            pass
        PROJECTS.pop(project_name, None)
        return json.dumps({"status": "already_closed"}, ensure_ascii=False)

    try:
        conn.send({"type": "close", "save": save})
        reply = conn.recv()
    except Exception as e:
        reply = {"ok": False, "error": str(e)}

    try:
        if proc.is_alive():
            proc.join(timeout=2.0)
    except Exception:
        pass
    if proc.is_alive():
        try:
            proc.terminate()
        except Exception:
            pass

    try:
        conn.close()
    except Exception:
        pass
    PROJECTS.pop(project_name, None)

    if not isinstance(reply, dict) or not reply.get("ok"):
        err = reply.get("error") if isinstance(reply, dict) else str(reply)
        raise RuntimeError(f"close_database failed: {err}")
    return json.dumps({"status": "closed"}, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="ida_domain MCP Server")
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    args = parser.parse_args()
    
    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            # NOTE: npx @modelcontextprotocol/inspector for debugging
            print(f"MCP Server availabile at http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass
    
if __name__ == "__main__":
    main()