"""双数据库并行分析测试脚本

启动方式示例：
	uv run ida-domain-mcp --transport http://127.0.0.1:8744
	uv run ida_domain_mcp/tests/test_ida_mcp.py http://127.0.0.1:8744/sse

测试目标：
1. 连接 ida-domain-mcp MCP Server (SSE 传输)
2. 使用 open_database 打开两个不同 project_name 对应的数据库（使用不同二进制）
3. 分别调用工具（get_metadata / get_entry_points / list_functions 等）验证互不干扰
4. 简单比对两个数据库的元数据与入口点列表是否存在差异
5. 关闭两个数据库

注意：
	- 服务器返回的各工具结果是 JSON 字符串，需要再 decode。
	- 如果分析尚未完成，可能出现函数列表暂时为空，可适当重试。
"""

import asyncio
import importlib
import json
import os
import sys
import time
from typing import Any, Dict, Optional, Callable

DEFAULT_SSE_URL = "http://127.0.0.1:8744/sse"


async def _call_tool(server: Any, tool_name: str, arguments: Optional[Dict[str, Any]] = None):
	"""通用工具调用，兼容不同客户端方法名。"""
	arguments = arguments or {}
	for meth in ("call_tool", "execute_tool"):
		fn = getattr(server, meth, None)
		if callable(fn):
			return await fn(tool_name, arguments)
	client = getattr(server, "client", None)
	if client is not None:
		for meth in ("call_tool", "execute_tool", "tools_call"):
			fn = getattr(client, meth, None)
			if callable(fn):
				try:
					return await fn(tool_name, arguments)
				except TypeError:
					payload = {"name": tool_name, "arguments": arguments}
					return await fn(payload)
	raise RuntimeError(f"无法在 server 上找到工具调用方法: {tool_name}")


async def _list_tools(server: Any):
	for meth in ("list_tools", "get_tools"):
		fn = getattr(server, meth, None)
		if callable(fn):
			return await fn()
	client = getattr(server, "client", None)
	if client is not None:
		for meth in ("list_tools", "get_tools", "tools_list"):
			fn = getattr(client, meth, None)
			if callable(fn):
				return await fn()
	return None


def _decode_json_field(payload: Any) -> Any:
	"""尽力从 MCP 返回对象中提取“业务数据”。
	优先读取 structuredContent.result，其次 content 文本，最后直接解析字符串。
	"""
	# 1) 处理对象形式（例如 CallToolResult）
	try:
		sc = getattr(payload, "structuredContent", None)
		if isinstance(sc, dict) and "result" in sc:
			data = sc.get("result")
			if isinstance(data, str):
				try:
					return json.loads(data)
				except Exception:
					return data
			return data
	except Exception:
		pass

	# 2) 尝试 content 列表（TextContent...）
	try:
		content = getattr(payload, "content", None)
		if isinstance(content, list) and content:
			# 尝试拼接文本
			texts = []
			for item in content:
				# item 可能是对象或 dict
				text = None
				if isinstance(item, dict):
					text = item.get("text")
				else:
					text = getattr(item, "text", None)
				if isinstance(text, str):
					texts.append(text)
			if texts:
				joined = "\n".join(texts)
				try:
					return json.loads(joined)
				except Exception:
					return joined
	except Exception:
		pass

	# 3) 直接处理 dict 结构
	if isinstance(payload, dict):
		# 常见封装 {"result": "{...json...}"}
		if "result" in payload:
			val = payload["result"]
			if isinstance(val, str):
				try:
					return json.loads(val)
				except Exception:
					return val
			return val
		return payload

	# 4) 字符串 JSON
	if isinstance(payload, str):
		try:
			return json.loads(payload)
		except Exception:
			return payload

	# 5) 其他类型原样返回（让上层按需处理/打印）
	return payload


async def _retry_tool(server: Any, tool_name: str, args: Dict[str, Any], predicate: Callable[[Any], bool], retries: int = 5, delay: float = 1.0):
	"""带重试的工具调用，直到 predicate 返回 True 或用尽次数。"""
	last = None
	for _ in range(retries):
		last = await _call_tool(server, tool_name, args)
		decoded = _decode_json_field(last)
		if predicate(decoded):
			return decoded
		await asyncio.sleep(delay)
	return _decode_json_field(last)


async def run_dual_database_test(sse_url: str):
	# 1. 动态导入 MCP 客户端
	try:
		mcp_mod = importlib.import_module("agents.mcp")
		MCPServerSse = getattr(mcp_mod, "MCPServerSse")
	except Exception:
		print("无法导入 agents.mcp。请安装 openai-agents 包。")
		sys.exit(1)

	print(f"连接 MCP 服务器: {sse_url}")
	server = MCPServerSse(
		params={"url": sse_url},
		cache_tools_list=True,
		name="ida-domain-mcp",
		client_session_timeout_seconds=120,
	)

	await server.connect()
	print("已连接。")

	tools = await _list_tools(server)
	if tools is None:
		print("无法列出工具，继续后续测试。")
	else:
		print("工具列表(截取/格式化显示)：")
		try:
			print(json.dumps(tools, ensure_ascii=False, indent=2, default=str)[:2000])
		except TypeError:
			print(str(tools))

	# 2. 打开两个数据库 (项目名称不同, 二进制不同)
	base_dir = os.path.dirname(__file__)
	bin_a = os.path.join(base_dir, "binaries", "a.out")
	bin_b = os.path.join(base_dir, "binaries", "crackme03.elf")
	if not os.path.exists(bin_a) or not os.path.exists(bin_b):
		print(f"测试二进制缺失: {bin_a} 或 {bin_b}")
		await server.cleanup()
		sys.exit(1)

	proj_a = "projA"
	proj_b = "projB"

	print(f"打开数据库: {proj_a} -> {bin_a}")
	r_open_a = _decode_json_field(await _call_tool(server, "open_database", {
		"project_name": proj_a,
		"db_path": bin_a,
		"auto_analysis": True,
		"new_database": False,
		"save_on_close": False,
	}))
	print("结果:", r_open_a)

	print(f"打开数据库: {proj_b} -> {bin_b}")
	r_open_b = _decode_json_field(await _call_tool(server, "open_database", {
		"project_name": proj_b,
		"db_path": bin_b,
		"auto_analysis": True,
		"new_database": False,
		"save_on_close": False,
	}))
	print("结果:", r_open_b)

	# 3. 获取元数据 (可能分析尚未完成，重试直到含有一些函数/段信息或超时)
	print("获取项目 A 元数据 ...")
	meta_a = await _retry_tool(server, "get_metadata", {"project_name": proj_a}, lambda d: isinstance(d, dict), retries=5)
	print("metaA:", json.dumps(meta_a, ensure_ascii=False, indent=2)[:1500])

	print("获取项目 B 元数据 ...")
	meta_b = await _retry_tool(server, "get_metadata", {"project_name": proj_b}, lambda d: isinstance(d, dict), retries=5)
	print("metaB:", json.dumps(meta_b, ensure_ascii=False, indent=2)[:1500])

	# 4. 获取入口点列表并比较
	print("获取项目 A 入口点列表 ...")
	entries_a_raw = await _call_tool(server, "get_entry_points", {"project_name": proj_a})
	entries_a = _decode_json_field(entries_a_raw)
	print("entriesA:", entries_a)

	print("获取项目 B 入口点列表 ...")
	entries_b_raw = await _call_tool(server, "get_entry_points", {"project_name": proj_b})
	entries_b = _decode_json_field(entries_b_raw)
	print("entriesB:", entries_b)

	# 5. 获取函数列表 (前 5 个) 便于差异对比
	def _func_list_pred(d: Any) -> bool:
		if isinstance(d, dict):
			# 可能格式 {"functions": [...]} 或其他；只要有内容即可
			for k in ("functions", "items", "result"):
				v = d.get(k)
				if isinstance(v, list) and len(v) > 0:
					return True
		return False

	print("列出项目 A 函数(重试)...")
	list_a = await _retry_tool(server, "list_functions", {"project_name": proj_a, "offset": 0, "count": 5}, _func_list_pred, retries=6)
	print("funcsA:", json.dumps(list_a, ensure_ascii=False, indent=2)[:1200])

	print("列出项目 B 函数(重试)...")
	list_b = await _retry_tool(server, "list_functions", {"project_name": proj_b, "offset": 0, "count": 5}, _func_list_pred, retries=6)
	print("funcsB:", json.dumps(list_b, ensure_ascii=False, indent=2)[:1200])

	# 6. 差异性检查（基本）
	diff_flags = []
	if meta_a == meta_b:
		diff_flags.append("元数据完全相同")
	if entries_a == entries_b:
		diff_flags.append("入口点列表完全相同")
	if list_a == list_b:
		diff_flags.append("函数列表完全相同")

	if diff_flags:
		print("[警告] 两个数据库结果存在高相似度: " + "; ".join(diff_flags))
	else:
		print("两个数据库内容存在差异，测试通过。")

	# 7. 关闭数据库
	print("关闭项目 A 数据库 ...")
	close_a = _decode_json_field(await _call_tool(server, "close_database", {"project_name": proj_a, "save": False}))
	print("closeA:", close_a)
	print("关闭项目 B 数据库 ...")
	close_b = _decode_json_field(await _call_tool(server, "close_database", {"project_name": proj_b, "save": False}))
	print("closeB:", close_b)

	await server.cleanup()
	print("已清理连接。")

	# 如果高度相似则返回非零退出码，方便集成检测
	if diff_flags:
		sys.exit(2)


def main():
	url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SSE_URL
	asyncio.run(run_dual_database_test(url))


if __name__ == "__main__":
	main()

