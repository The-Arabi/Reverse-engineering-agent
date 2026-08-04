"""
MCP (Model Context Protocol) Server Template
Standard interface for connecting agents to analysis tools
"""

import abc
import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import websockets
import aiohttp
from datetime import datetime


class MCPMessageType(Enum):
    """Types of MCP messages"""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


@dataclass
class MCPMessage:
    """Standard MCP message structure"""
    jsonrpc: str = "2.0"
    id: Optional[str] = None
    method: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPMessage':
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})


class MCPError(Exception):
    """MCP-specific error"""
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"MCP Error {code}: {message}")


class BaseMCPServer(abc.ABC):
    """Base class for MCP servers that connect to analysis tools"""

    def __init__(self, server_name: str, host: str = "localhost", port: int = 8000):
        self.server_name = server_name
        self.host = host
        self.port = port
        self.logger = logging.getLogger(f"mcp.{server_name}")
        self.methods: Dict[str, Callable] = {}
        self.connected_clients: set = set()
        self.is_running = False
        self.server = None

    def register_method(self, name: str, handler: Callable):
        """Register a method handler"""
        self.methods[name] = handler
        self.logger.debug(f"Registered MCP method: {name}")

    def unregister_method(self, name: str):
        """Unregister a method handler"""
        if name in self.methods:
            del self.methods[name]
            self.logger.debug(f"Unregistered MCP method: {name}")

    async def handle_message(self, websocket, message: str):
        """Handle incoming MCP message"""
        try:
            data = json.loads(message)
            mcp_msg = MCPMessage.from_dict(data)

            self.logger.debug(f"Received MCP message: {mcp_msg.method}")

            if mcp_msg.method not in self.methods:
                error_response = MCPMessage(
                    id=mcp_msg.id,
                    error={
                        "code": -32601,
                        "message": f"Method not found: {mcp_msg.method}"
                    }
                )
                await websocket.send(json.dumps(error_response.to_dict()))
                return

            # Execute the method
            try:
                result = await self.methods[mcp_msg.method](mcp_msg.params or {})
                response = MCPMessage(
                    id=mcp_msg.id,
                    result=result
                )
            except Exception as e:
                self.logger.error(f"Error executing method {mcp_msg.method}: {e}")
                response = MCPMessage(
                    id=mcp_msg.id,
                    error={
                        "code": -32603,
                        "message": f"Internal error: {str(e)}"
                    }
                )

            await websocket.send(json.dumps(response.to_dict()))

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON received: {e}")
            error_response = MCPMessage(
                error={
                    "code": -32700,
                    "message": "Parse error"
                }
            )
            await websocket.send(json.dumps(error_response.to_dict()))
        except Exception as e:
            self.logger.error(f"Error handling MCP message: {e}")

    async def handle_client(self, websocket, path):
        """Handle a client connection"""
        client_id = id(websocket)
        self.connected_clients.add(websocket)
        self.logger.info(f"Client connected: {client_id}")

        try:
            async for message in websocket:
                await self.handle_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            self.logger.info(f"Client disconnected: {client_id}")
        except Exception as e:
            self.logger.error(f"Error in client handler: {e}")
        finally:
            self.connected_clients.discard(websocket)

    async def start(self):
        """Start the MCP server"""
        if self.is_running:
            self.logger.warning("Server is already running")
            return

        self.logger.info(f"Starting MCP server {self.server_name} on {self.host}:{self.port}")
        self.server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port
        )
        self.is_running = True
        self.logger.info(f"MCP server {self.server_name} started")

    async def stop(self):
        """Stop the MCP server"""
        if not self.is_running:
            self.logger.warning("Server is not running")
            return

        self.logger.info(f"Stopping MCP server {self.server_name}")
        self.server.close()
        await self.server.wait_closed()
        self.is_running = False
        self.logger.info(f"MCP server {self.server_name} stopped")

    async def call_method(self, method: str, params: Dict[str, Any] = None) -> Any:
        """Call a method on this server (for testing)"""
        if method not in self.methods:
            raise MCPError(-32601, f"Method not found: {method}")

        try:
            return await self.methods[method](params or {})
        except Exception as e:
            raise MCPError(-32603, f"Internal error: {str(e)}")


class BaseMCPClient:
    """Base class for MCP clients that connect to MCP servers"""

    def __init__(self, server_name: str, host: str = "localhost", port: int = 8000):
        self.server_name = server_name
        self.host = host
        self.port = port
        self.logger = logging.getLogger(f"mcp_client.{server_name}")
        self.websocket = None
        self.connected = False
        self.request_id = 0
        self.pending_requests: Dict[str, asyncio.Future] = {}

    def _get_next_id(self) -> str:
        """Get next request ID"""
        self.request_id += 1
        return str(self.request_id)

    async def connect(self):
        """Connect to the MCP server"""
        if self.connected:
            self.logger.warning("Already connected")
            return

        uri = f"ws://{self.host}:{self.port}"
        self.logger.info(f"Connecting to MCP server {self.server_name} at {uri}")

        try:
            self.websocket = await websockets.connect(uri)
            self.connected = True
            self.logger.info(f"Connected to MCP server {self.server_name}")

            # Start listening for responses
            asyncio.create_task(self._listen_for_responses())

        except Exception as e:
            self.logger.error(f"Failed to connect to MCP server: {e}")
            raise

    async def disconnect(self):
        """Disconnect from the MCP server"""
        if not self.connected:
            return

        self.logger.info(f"Disconnecting from MCP server {self.server_name}")
        if self.websocket:
            await self.websocket.close()
        self.connected = False
        self.logger.info(f"Disconnected from MCP server {self.server_name}")

    async def _listen_for_responses(self):
        """Listen for responses from the server"""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    mcp_msg = MCPMessage.from_dict(data)

                    if mcp_msg.id and mcp_msg.id in self.pending_requests:
                        future = self.pending_requests.pop(mcp_msg.id)
                        if not future.done():
                            if mcp_msg.error:
                                future.set_exception(MCPError(
                                    mcp_msg.error.get("code", -32603),
                                    mcp_msg.error.get("message", "Unknown error"),
                                    mcp_msg.error.get("data")
                                ))
                            else:
                                future.set_result(mcp_msg.result)
                    else:
                        # Notification or unknown response
                        self.logger.debug(f"Received unsolicited message: {mcp_msg.method}")

                except json.JSONDecodeError as e:
                    self.logger.error(f"Invalid JSON received: {e}")
                except Exception as e:
                    self.logger.error(f"Error processing message: {e}")

        except websockets.exceptions.ConnectionClosed:
            self.logger.info("Connection to MCP server closed")
            self.connected = False
        except Exception as e:
            self.logger.error(f"Error in listener: {e}")
            self.connected = False

    async def call_method(self, method: str, params: Dict[str, Any] = None, timeout: float = 30.0) -> Any:
        """Call a method on the MCP server"""
        if not self.connected:
            raise MCPError(-32603, "Not connected to MCP server")

        request_id = self._get_next_id()
        request = MCPMessage(
            id=request_id,
            method=method,
            params=params or {}
        )

        # Create future for response
        future = asyncio.Future()
        self.pending_requests[request_id] = future

        try:
            # Send request
            await self.websocket.send(json.dumps(request.to_dict()))

            # Wait for response with timeout
            result = await asyncio.wait_for(future, timeout=timeout)
            return result

        except asyncio.TimeoutError:
            self.pending_requests.pop(request_id, None)
            raise MCPError(-32603, f"Request timeout for method {method}")
        except Exception as e:
            self.pending_requests.pop(request_id, None)
            raise MCPError(-32603, f"Failed to call method {method}: {str(e)}")


# Specific MCP implementations for different tools

class BinaryAnalysisMCPServer(BaseMCPServer):
    """MCP server for binary analysis tools (Ghidra, IDA, Binary Ninja, radare2)"""

    def __init__(self, host: str = "localhost", port: int = 8001):
        super().__init__("binary_analysis", host, port)
        self._register_core_methods()

    def _register_core_methods(self):
        """Register core binary analysis methods"""
        self.register_method("analyze_binary", self._analyze_binary)
        self.register_method("get_function", self._get_function)
        self.register_method("rename_function", self._rename_function)
        self.register_method("generate_call_graph", self._generate_call_graph)
        self.register_method("search_strings", self._search_strings)
        self.register_method("find_references", self._find_references)
        self.register_method("compare_versions", self._compare_versions)

    async def _analyze_binary(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a binary file"""
        # This would integrate with actual binary analysis tools
        file_path = params.get("file_path")
        analysis_type = params.get("analysis_type", "basic")

        self.logger.info(f"Analyzing binary: {file_path} (type: {analysis_type})")

        # Placeholder implementation
        return {
            "file_path": file_path,
            "analysis_type": analysis_type,
            "entry_point": "0x400000",
            "functions_found": 0,
            "strings_found": 0,
            "imports": [],
            "exports": [],
            "analysis_time": 0.0
        }

    async def _get_function(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get information about a specific function"""
        address = params.get("address")
        function_name = params.get("name")

        self.logger.info(f"Getting function info: {address or function_name}")

        return {
            "address": address,
            "name": function_name or f"func_{address}",
            "size": 0,
            "signature": "",
            "calling_convention": "",
            "return_type": "void",
            "parameters": [],
            "called_by": [],
            "calls": []
        }

    async def _rename_function(self, params: Dict[str, Any]) -> bool:
        """Rename a function"""
        address = params.get("address")
        new_name = params.get("new_name")

        self.logger.info(f"Renaming function at {address} to {new_name}")
        return True

    async def _generate_call_graph(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate call graph for the binary"""
        format_type = params.get("format", "dot")
        depth = params.get("depth", -1)

        self.logger.info(f"Generating call graph (format: {format_type}, depth: {depth})")
        return {
            "format": format_type,
            "nodes": 0,
            "edges": 0,
            "data": "// Call graph data would go here"
        }

    async def _search_strings(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search for strings in the binary"""
        query = params.get("query", "")
        case_sensitive = params.get("case_sensitive", False)
        max_results = params.get("max_results", 100)

        self.logger.info(f"Searching for strings: '{query}' (case_sensitive: {case_sensitive})")
        return [
            {
                "address": "0x401000",
                "string": "example string",
                "length": len("example string"),
                "section": ".rodata"
            }
        ]

    async def _find_references(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find references to an address or symbol"""
        address = params.get("address")
        symbol = params.get("symbol")
        reference_type = params.get("type", "all")

        self.logger.info(f"Finding references to: {address or symbol} (type: {reference_type})")
        return [
            {
                "address": "0x402000",
                "instruction": "call 0x401000",
                "type": "call"
            }
        ]

    async def _compare_versions(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Compare two versions of a binary"""
        file1 = params.get("file1")
        file2 = params.get("file2")
        comparison_type = params.get("type", "structural")

        self.logger.info(f"Comparing {file1} with {file2} (type: {comparison_type})")
        return {
            "file1": file1,
            "file2": file2,
            "comparison_type": comparison_type,
            "similarity_score": 0.0,
            "differences": [],
            "new_functions": [],
            "removed_functions": [],
            "modified_functions": []
        }


class DebuggerMCPServer(BaseMCPServer):
    """MCP server for debugger functionality"""

    def __init__(self, host: str = "localhost", port: int = 8002):
        super().__init__("debugger", host, port)
        self._register_core_methods()

    def _register_core_methods(self):
        """Register core debugger methods"""
        self.register_method("set_breakpoint", self._set_breakpoint)
        self.register_method("remove_breakpoint", self._remove_breakpoint)
        self.register_method("read_memory", self._read_memory)
        self.register_method("write_memory", self._write_memory)
        self.register_method("read_registers", self._read_registers)
        self.register_method("write_registers", self._write_registers)
        self.register_method("trace_execution", self._trace_execution)
        self.register_method("get_registers", self._get_registers)
        self.register_method("set_register", self._set_register)
        self.register_method("continue_execution", self._continue_execution)
        self.register_method("step_instruction", self._step_instruction)
        self.register_method("step_over", self._step_over)
        self.register_method("step_out", self._step_out)
        self.register_method("halt", self._halt)
        self.register_method("dump_state", self._dump_state)

    async def _set_breakpoint(self, params: Dict[str, Any]) -> bool:
        """Set a breakpoint"""
        address = params.get("address")
        condition = params.get("condition")
        self.logger.info(f"Setting breakpoint at {address} (condition: {condition})")
        return True

    async def _remove_breakpoint(self, params: Dict[str, Any]) -> bool:
        """Remove a breakpoint"""
        address = params.get("address")
        self.logger.info(f"Removing breakpoint at {address}")
        return True

    async def _read_memory(self, params: Dict[str, Any]) -> List[int]:
        """Read memory from the target process"""
        address = params.get("address")
        length = params.get("length", 16)
        self.logger.info(f"Reading {length} bytes from {address}")
        return [0x00] * length  # Placeholder

    async def _write_memory(self, params: Dict[str, Any]) -> bool:
        """Write memory to the target process"""
        address = params.get("address")
        data = params.get("data", [])
        self.logger.info(f"Writing {len(data)} bytes to {address}")
        return True

    async def _read_registers(self, params: Dict[str, Any]) -> Dict[str, int]:
        """Read CPU registers"""
        register_names = params.get("registers", [])
        self.logger.info(f"Reading registers: {register_names}")
        return {reg: 0x00 for reg in register_names}

    async def _write_registers(self, params: Dict[str, Any]) -> bool:
        """Write CPU registers"""
        registers = params.get("registers", {})
        self.logger.info(f"Writing registers: {list(registers.keys())}")
        return True

    async def _trace_execution(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Trace program execution"""
        start_address = params.get("start_address")
        end_address = params.get("end_address")
        max_instructions = params.get("max_instructions", 1000)
        self.logger.info(f"Tracing execution from {start_address} to {end_address} (max {max_instructions} instructions)")
        return []

    async def _get_registers(self, params: Dict[str, Any]) -> Dict[str, int]:
        """Get all CPU registers"""
        self.logger.info("Getting all registers")
        return {
            "rax": 0x00, "rbx": 0x00, "rcx": 0x00, "rdx": 0x00,
            "rsi": 0x00, "rdi": 0x00, "rbp": 0x00, "rsp": 0x00,
            "r8": 0x00, "r9": 0x00, "r10": 0x00, "r11": 0x00,
            "r12": 0x00, "r13": 0x00, "r14": 0x00, "r15": 0x00,
            "rip": 0x00, "eflags": 0x00
        }

    async def _set_register(self, params: Dict[str, Any]) -> bool:
        """Set a specific CPU register"""
        register = params.get("register")
        value = params.get("value")
        self.logger.info(f"Setting register {register} to {value:#x}")
        return True

    async def _continue_execution(self, params: Dict[str, Any]) -> bool:
        """Continue program execution"""
        self.logger.info("Continuing execution")
        return True

    async def _step_instruction(self, params: Dict[str, Any]) -> bool:
        """Single step one instruction"""
        self.logger.info("Single stepping instruction")
        return True

    async def _step_over(self, params: Dict[str, Any]) -> bool:
        """Step over (skip function calls)"""
        self.logger.info("Step over")
        return True

    async def _step_out(self, params: Dict[str, Any]) -> bool:
        """Step out of current function"""
        self.logger.info("Step out")
        return True

    async def _halt(self, params: Dict[str, Any]) -> bool:
        """Halt program execution"""
        self.logger.info("Halting execution")
        return True

    async def _dump_state(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Dump complete processor and memory state"""
        self.logger.info("Dumping system state")
        return {
            "registers": await self._get_registers({}),
            "memory_map": [],
            "stack": [],
            "breakpoints": []
        }


class BinaryAnalysisMCPClient(BaseMCPClient):
    """MCP client for connecting to a binary analysis MCP server"""

    def __init__(self, host: str = "localhost", port: int = 8001):
        super().__init__("binary_analysis", host, port)

    async def analyze_binary(self, file_path: str, analysis_type: str = "comprehensive", **kwargs) -> Any:
        """Analyze a binary file"""
        return await self.call_method("analyze_binary", {
            "file_path": file_path,
            "analysis_type": analysis_type,
            **kwargs
        })

    async def search_strings(self, file_path: str, min_length: int = 4, encoding: str = "ascii") -> Any:
        """Search for strings in a binary"""
        return await self.call_method("search_strings", {
            "file_path": file_path,
            "min_length": min_length,
            "encoding": encoding
        })

    async def get_imports(self, file_path: str) -> Any:
        """Get imported symbols from a binary"""
        return await self.call_method("get_imports", {"file_path": file_path})

    async def get_functions(self, file_path: str, include_decompiled: bool = False) -> Any:
        """Get functions from a binary"""
        return await self.call_method("get_functions", {
            "file_path": file_path,
            "include_decompiled": include_decompiled
        })

    async def rename_function(self, file_path: str, address: str, new_name: str) -> Any:
        """Rename a function in a binary"""
        return await self.call_method("rename_function", {
            "file_path": file_path,
            "address": address,
            "new_name": new_name
        })

    async def generate_call_graph(self, file_path: str) -> Any:
        """Generate a call graph for a binary"""
        return await self.call_method("generate_call_graph", {"file_path": file_path})

    async def find_references(self, file_path: str, target: str) -> Any:
        """Find references to a symbol in a binary"""
        return await self.call_method("find_references", {
            "file_path": file_path,
            "target": target
        })


# Factory function to create MCP servers
def create_mcp_server(server_type: str, host: str = "localhost", port: int = None) -> BaseMCPServer:
    """Factory function to create MCP servers"""
    if server_type == "binary_analysis":
        return BinaryAnalysisMCPServer(host, port or 8001)
    elif server_type == "debugger":
        return DebuggerMCPServer(host, port or 8002)
    else:
        raise ValueError(f"Unknown MCP server type: {server_type}")


# Example usage
if __name__ == "__main__":
    import asyncio
    import logging

    logging.basicConfig(level=logging.INFO)

    async def main():
        # Create and start a binary analysis MCP server
        server = BinaryAnalysisMCPServer(port=8001)
        await server.start()

        try:
            # Keep server running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            await server.stop()

    # Run the example
    asyncio.run(main())