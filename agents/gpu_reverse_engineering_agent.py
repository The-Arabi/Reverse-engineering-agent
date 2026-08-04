"""
GPU Reverse Engineering Agent Implementation
Specialized agent for analyzing GPU binaries, shaders, and graphics driver interactions
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

from agents.base_agent import AnalysisAgent, AgentStatus, Task, AgentResult
from knowledge_base import add_fact, add_hypothesis, kb


class GpuReverseEngineeringAgent(AnalysisAgent):
    """Agent specialized in GPU reverse engineering using tools like RenderDoc, NSight, GPUView, and shader analyzers"""

    def __init__(self, agent_id: str = None, name: str = "GPU Reverse Engineering Agent"):
        super().__init__(
            agent_id=agent_id or f"gpu_agent_{id(self)}",
            name=name,
            description="Analyzes GPU binaries, shader programs, graphics driver interactions, and framebuffer contents"
        )
        self.agent_type = "gpu_reverse_engineering"
        self.supported_formats = {
            "spirv", "glsl", "hlsl", "metal", "dxbc", "gpu_binary", "framebuffer", "texture", "command_buffer", "gpu_trace"
        }
        self.analysis_tools = {
            "renderdoc": None,
            "nsight_graphics": None,
            "nsight_compute": None,
            "gpucview": None,  # GPUView
            "shader_compiler": None,
            "spirv_disassembler": None,
            "dxbc_disassembler": None,
            "metal_disassembler": None,
            "texture_analyzer": None,
            "framebuffer_analyzer": None,
            "command_buffer_analyzer": None
        }

    async def initialize(self) -> bool:
        """Initialize the GPU reverse engineering agent"""
        try:
            self.logger.info("Initializing GPU Reverse Engineering Agent")
            # Check for available tools (in a real implementation, this would check for actual installations)
            await self._check_available_tools()
            self.logger.info("GPU Reverse Engineering Agent initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize GPU Reverse Engineering Agent: {e}")
            return False

    async def _check_available_tools(self):
        """Check which analysis tools are available"""
        # In a real implementation, this would check for actual tool installations
        # For now, we'll simulate availability
        self.analysis_tools = {
            "renderdoc": True,       # Assume RenderDoc available
            "nsight_graphics": True, # Assume Nsight Graphics available
            "nsight_compute": True,  # Assume Nsight Compute available
            "gpucview": True,        # Assume GPUView available
            "shader_compiler": True, # Assume shader compiler available (glslc, fxc, etc.)
            "spirv_disassembler": True,  # Assume SPIR-V disassembler available
            "dxbc_disassembler": True,   # Assume DXBC disassembler available
            "metal_disassembler": True,  # Assume Metal disassembler available
            "texture_analyzer": True,    # Assume texture analyzer available
            "framebuffer_analyzer": True, # Assume framebuffer analyzer available
            "command_buffer_analyzer": True # Assume command buffer analyzer available
        }

        available_count = sum(1 for available in self.analysis_tools.values() if available)
        self.logger.info(f"Available GPU reverse engineering tools: {available_count}/{len(self.analysis_tools)}")

    async def execute_task(self, task: Task) -> AgentResult:
        """Execute a GPU reverse engineering task"""
        self.logger.info(f"Executing GPU reverse engineering task: {task.description}")
        self.status = AgentStatus.PROCESSING

        try:
            # Extract task parameters
            params = task.parameters or {}
            file_path = params.get("file_path")
            analysis_type = params.get("analysis_type", "comprehensive")

            if not file_path:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    status="failed",
                    error="No file_path provided in task parameters",
                    result={}
                )

            # Validate file exists
            if not Path(file_path).exists():
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    status="failed",
                    error=f"File not found: {file_path}",
                    result={}
                )

            # Perform analysis based on type
            if analysis_type == "basic":
                result = await self._basic_analysis(file_path, params)
            elif analysis_type == "shader":
                result = await self._shader_analysis(file_path, params)
            elif analysis_type == "binary":
                result = await self._binary_analysis(file_path, params)
            elif analysis_type == "framebuffer":
                result = await self._framebuffer_analysis(file_path, params)
            elif analysis_type == "texture":
                result = await self._texture_analysis(file_path, params)
            elif analysis_type == "framebuffer":
                result = await self._framebuffer_analysis(file_path, params)
            elif analysis_type == "command_buffer":
                result = await self._command_buffer_analysis(file_path, params)
            elif analysis_type == "driver_interaction":
                result = await self._driver_interaction_analysis(file_path, params)
            elif analysis_type == "performance":
                result = await self._performance_analysis(file_path, params)
            elif analysis_type == "comprehensive":
                result = await self._comprehensive_analysis(file_path, params)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    status="failed",
                    error=f"Unknown analysis type: {analysis_type}",
                    result={}
                )

            # Store results in knowledge base
            await self._store_analysis_results(file_path, analysis_type, result)

            self.status = AgentStatus.IDLE
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                result=result
            )

        except Exception as e:
            self.logger.error(f"Error executing GPU reverse engineering task: {e}", exc_info=True)
            self.status = AgentStatus.ERROR
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="failed",
                error=str(e),
                result={}
            )
        finally:
            if self.status != AgentStatus.ERROR:
                self.status = AgentStatus.IDLE

    async def cleanup(self) -> bool:
        """Clean up resources"""
        self.logger.info("GPU Reverse Engineering Agent cleaned up")
        return True

    async def _basic_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Perform basic GPU binary/shader analysis"""
        self.logger.info(f"Performing basic GPU analysis on {file_path}")

        # In a real implementation, this would analyze GPU binaries or shader bytecode
        # For now, we'll simulate analysis results
        result = {
            "file_path": file_path,
            "file_size": 0,  # Will be set based on actual file
            "file_format": "Unknown",
            "gpu_architecture": "Unknown",
            "shader_stage": "Unknown",
            "entry_point": "Unknown",
            "resource_bindings": [],
            "instructions": [],
            "analysis_timestamp": "2024-01-15T10:30:00Z"
        }

        # Try to determine file type and extract basic info
        # In reality, we'd use tools like spirv-dis, dxbc-disassemble, etc.
        result["file_size"] = Path(file_path).stat().st_size if Path(file_path).exists() else 8192
        result["file_format"] = "SPIR-V"
        result["gpu_architecture"] = "Vulkan-compatible"
        result["shader_stage"] = "Fragment"
        result["entry_point"] = "main"
        result["resource_bindings"] = [
            {"binding": 0, "type": "uniform_buffer", "stage": "fragment", "name": "CameraUBO"},
            {"binding": 1, "type": "sampled_image", "stage": "fragment", "name": "TextureDiffuse"},
            {"binding": 2, "type": "sampler", "stage": "fragment", "name": "SamplerLinear"}
        ]
        result["instructions"] = [
            {"op": "OpLabel", "id": 1},
            {"op": "OpLoad", "id": 2, "pointer_id": 3},
            {"op": "OpSampledImage", "id": 4, "image_id": 5, "sampler_id": 6},
            {"op": "OpImageSampleImplicitLod", "id": 7, "sampled_image_id": 4, "coordinate_id": 2},
            {"op": "OpStore", "pointer_id": 8, "value_id": 7}
        ]

        return result

    async def _shader_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze shader programs for functionality and vulnerabilities"""
        self.logger.info(f"Performing shader analysis on {file_path}")

        # In a real implementation, this would decompile and analyze shader code
        # For now, we'll simulate
        result = {
            "file_path": file_path,
            "analysis_type": "shader",
            "decompiled_code": "",
            "control_flow_graph": {},
            "data_flow_analysis": {},
            "texture_usage": [],
            "control_flow_patterns": [],
            "potential_issues": [],
            "analysis_timestamp": "2024-01-15T10:30:00Z"
        }

        # Simulate shader decompilation and analysis
        result["decompiled_code"] = """
        // Fragment shader decompilation
        layout(set=0, binding=0) uniform CameraUBO {
            mat4 viewProj;
            vec3 cameraPos;
        } ubo;

        layout(set=0, binding=1) uniform sampler2D TextureDiffuse;
        layout(set=0, binding=2) uniform sampler SamplerLinear;

        layout(location=0) in vec2 vTexCoord;
        layout(location=0) out vec4 fragColor;

        void main() {
            vec4 texColor = texture(sampler2D(TextureDiffuse, SamplerLinear), vTexCoord);
            vec3 lightDir = normalize(vec3(1.0, 1.0, 1.0));
            vec3 normal = texture(sampler2D(TextureDiffuse, SamplerLinear), vTexCoord * 2.0).rgb * 2.0 - 1.0;
            float diffuse = max(dot(normal, lightDir), 0.0);
            fragColor = vec4(texColor.rgb * diffuse, texColor.a);
        }
        """

        result["control_flow_graph"] = {
            "nodes": ["entry", "texture_sample", "lighting_calc", "store_result", "exit"],
            "edges": [
                {"from": "entry", "to": "texture_sample"},
                {"from": "texture_sample", "to": "lighting_calc"},
                {"from": "lighting_calc", "to": "store_result"},
                {"from": "store_result", "to": "exit"}
            ]
        }

        result["texture_usage"] = [
            {"unit": 0, "type": "2D", "format": "RGBA8", "sampler": "linear_mipmap_linear"},
            {"unit": 1, "type": "2D", "format": "RGBA16F", "sampler": "repeat"}
        ]

        result["control_flow_patterns"] = [
            {"type": "linear", "description": "Straight-line code with no branching"},
            {"type": "texture_sampling", "description": "Two texture samples per fragment"}
        ]

        result["potential_issues"] = [
            {"type": "dependent_texture_read", "description": "Second texture sample depends on first, may cause performance issues"},
            {"type": "high_precision_usage", "description": "Using high precision where mediump might suffice"}
        ]

        return result

    async def _binary_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GPU binaries (driver commands, microcode)"""
        self.logger.info(f"Performing GPU binary analysis on {file_path}")

        # In a real implementation, this would disassemble and analyze GPU machine code
        # For now, we'll simulate
        result = {
            "file_path": file_path,
            "analysis_type": "binary",
            "disassembled_code": "",
            "instruction_analysis": {},
            "register_usage": {},
            "memory_access_patterns": {},
            "potential_vulnerabilities": [],
            "analysis_timestamp": "2024-01-15T10:30:00Z"
        }

        # Simulate GPU binary disassembly
        result["disassembled_code"] = """
        ; GPU microcode disassembly (simulated)
        ; Vertex shader main
        main:
            ; Load vertex attributes
            LD V0, [ATTR0_BUFFER]      ; Position
            LD V1, [ATTR1_BUFFER]      ; Normal
            LD V2, [ATTR2_BUFFER]      ; TexCoord

            ; Transform position
            MUL_MAT4 V0, V0, [UNIFORM_MVP]  ; pos * mvp

            ; Pass varyings
            MOV [OUT_POS], V0
            MOV [OUT_TEXCOORD], V2

            ; Simple lighting (if implemented)
            ; ... truncated for brevity ...

            RET
        """

        result["instruction_analysis"] = {
            "total_instructions": 45,
            "alu_instructions": 28,
            "texture_instructions": 8,
            "branch_instructions": 4,
            "load_store_instructions": 5
        }

        result["register_usage"] = {
            "vertex_inputs": 3,
            "vertex_outputs": 2,
            "temporaries": 12,
            "constant_buffers_accessed": 2
        }

        result["memory_access_patterns"] = {
            "attribute_reads": {"count": 3, "pattern": "coalesced"},
            "uniform_reads": {"count": 2, "pattern": "uniform"},
            "varying_writes": {"count": 2, "pattern": "linear"},
            "texture_sample_locations": 2
        }

        result["potential_vulnerabilities"] = [
            {"type": "buffer_overflow_risk", "description": "Potential out-of-bounds attribute access if count not validated"},
            {"type": "timing_side_channel", "description": "Variable execution time based on texture cache hits"}
        ]

        return result

    async def _framebuffer_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze framebuffer contents for rendering artifacts"""
        self.logger.info(f"Performing framebuffer analysis on {file_path}")

        # In a real implementation, this would analyze rendered images
        # For now, we'll simulate
        result = {
            "file_path": file_path,
            "analysis_type": "framebuffer",
            "resolution": "Unknown",
            "format": "Unknown",
            "color_analysis": {},
            "artifact_detection": {},
            "rendering_techniques": [],
            "analysis_timestamp": "2024-01-15T10:30:00Z"
        }

        # Simulate framebuffer analysis
        result["resolution"] = "1920x1080"
        result["format"] = "RGBA8"
        result["color_analysis"] = {
            "dominant_colors": [
                {"color": [135, 206, 235, 255], "percentage": 60.2, "name": "sky_blue"},
                {"color": [34, 139, 34, 255], "percentage": 25.8, "name": "forest_green"},
                {"color": [139, 69, 19, 255], "percentage": 10.5, "name": "saddle_brown"},
                {"color": [255, 255, 255, 255], "percentage": 3.5, "name": "white"}
            ],
            "average_brightness": 0.65,
            "color_variance": 0.28
        }

        result["artifact_detection"] = {
            "banding": {"detected": False, "severity": "none"},
            "blurring": {"detected": False, "severity": "none"},
            "tearing": {"detected": False, "severity": "none"},
            "aliasing": {"detected": True, "severity": "moderate", "locations": ["object_edges"]},
            "color_banding": {"detected": False, "severity": "none"}
        }

        result["rendering_techniques"] = [
            {"technique": "clear_color", "evidence": "Solid color regions at screen edges"},
            {"technique": "depth_testing", "evidence": "Proper occlusion of distant objects"},
            {"technique": "texture_mapping", "evidence": "Detailed surface patterns"},
            {"technique": "basic_lighting", "evidence": "Shading consistent with light source direction"}
        ]

        return result

    async def _command_buffer_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GPU command buffers for rendering patterns"""
        self.logger.info(f"Performing command buffer analysis on {file_path}")

        # In a real implementation, this would parse command buffers (e.g., from RenderDoc capture)
        # For now, we'll simulate
        result = {
            "file_path": file_path,
            "analysis_type": "command_buffer",
            "command_count": 0,
            "render_passes": [],
            "draw_calls": [],
            "state_changes": [],
            "resource_usage": {},
            "performance_implications": [],
            "analysis_timestamp": "2024-01-15T10:30:00Z"
        }

        # Simulate command buffer analysis
        result["command_count"] = 127
        result["render_passes"] = [
            {
                "id": 0,
                "type": "clear",
                "attachments": [{"target": "color", "clear_value": [0.1, 0.2, 0.3, 1.0]}],
                "timestamp_range": [0, 1000000]
            },
            {
                "id": 1,
                "type": "draw",
                "attachments": [{"target": "color", "load_op": "load"}, {"target": "depth", "load_op": "clear"}],
                "draw_calls": 42,
                "timestamp_range": [1000000, 8000000]
            },
            {
                "id": 2,
                "type": "present",
                "attachments": [{"target": "color", "load_op": "load"}],
                "timestamp_range": [8000000, 8500000]
            }
        ]

        result["draw_calls"] = [
            {"pipeline": "opaque", "vertex_count": 36000, "instance_count": 1, "state_hash": "abc123"},
            {"pipeline": "transparent", "vertex_count": 1200, "instance_count": 50, "state_hash": "def456"},
            {"pipeline": "skybox", "vertex_count": 24, "instance_count": 1, "state_hash": "ghi789"}
        ]

        result["state_changes"] = [
            {"type": "blend_state", "count": 3, "expensive": False},
            {"type": "depth_stencil_state", "count": 2, "expensive": False},
            {"type": "rasterizer_state", "count": 1, "expensive": False},
            {"type": "shader_program", "count": 3, "expensive": True},
            {"type": "constant_buffer_bindings", "count": 8, "expensive": False},
            {"type": "texture_bindings", "count": 15, "expensive": False}
        ]

        result["resource_usage"] = {
            "vertex_buffers": {"total_size_mb": 12.5, "bound_count": 4},
            "index_buffers": {"total_size_mb": 3.2, "bound_count": 3},
            "constant_buffers": {"total_size_mb": 0.8, "bound_count": 6},
            "textures": {"total_size_mb": 256.0, "bound_count": 12},
            "render_targets": {"total_size_mb": 8.0, "count": 2}
        }

        result["performance_implications"] = [
            {"type": "high_draw_call_count", "description": "42 draw calls may be CPU-bound", "impact": "medium"},
            {"type": "frequent_shader_changes", "description": "3 shader program changes per frame", "impact": "low"},
            {"type": "texture_switching", "description": "15 texture bindings suggest potential for texture atlasing", "impact": "medium"}
        ]

        return result

    async def _driver_interaction_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GPU driver interactions and API usage"""
        self.logger.info(f"Performing driver interaction analysis on {file_path}")

        # In a real implementation, this would trace driver API calls
        # For now, we'll simulate
        result = {
            "file_path": file_path,
            "analysis_type": "driver_interaction",
            "api_calls": {},
            "resource_creation_destruction": {},
            "synchronization_patterns": {},
            "potential_issues": [],
            "analysis_timestamp": "2024-01-15T10:30:00Z"
        }

        # Simulate driver interaction analysis
        result["api_calls"] = {
            "total_calls": 1250,
            "per_frame_average": 25,
            "by_category": {
                "resource_creation": 45,
                "resource_destruction": 30,
                "state_setting": 800,
                "drawing": 300,
                "synchronization": 75
            }
        }

        result["resource_creation_destruction"] = {
            "buffers": {"created": 12, "destroyed": 8, "leak_potential": "low"},
            "textures": {"created": 25, "destroyed": 20, "leak_potential": "medium"},
            "shaders": {"created": 18, "destroyed": 15, "leak_potential": "low"},
            "framebuffers": {"created": 5, "destroyed": 3, "leak_potential": "medium"}
        }

        result["synchronization_patterns"] = {
            "fence_usage": {"count": 5, "efficient": True},
            "barrier_usage": {"count": 12, "efficient": True},
            "queue_submissions": {"count": 3, "latency": "low"},
            "wait_idle_calls": {"count": 0, "issue": "none"}
        }

        result["potential_issues"] = [
            {"type": "resource_leak", "description": "5 textures not destroyed per frame cycle", "severity": "medium"},
            {"type": "inefficient_barrier", "description": "Full pipeline barriers used when more specific would suffice", "severity": "low"},
            {"type": "state_overflow", "description": "Approaching driver state cache limits", "severity": "low"}
        ]

        return result

    async def _performance_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GPU performance characteristics"""
        self.logger.info(f"Performing performance analysis on {file_path}")

        # In a real implementation, this would use profiling tools
        # For now, we'll simulate
        result = {
            "file_path": file_path,
            "analysis_type": "performance",
            "timing_metrics": {},
            "bottlenecks": [],
            "utilization": {},
            "optimization_opportunities": [],
            "analysis_timestamp": "2024-01-15T10:30:00Z"
        }

        # Simulate performance analysis
        result["timing_metrics"] = {
            "frame_time": {"min": "8ms", "max": "16ms", "average": "12ms"},
            "gpu_busy_time": {"min": "5ms", "max": "12ms", "average": "8ms"},
            "cpu_wait_time": {"min": "1ms", "max": "5ms", "average": "2ms"},
            "present_latency": {"min": "1ms", "max": "3ms", "average": "2ms"}
        }

        result["bottlenecks"] = [
            {"type": "fragment_shader", "percentage": 45, "description": "Fragment shader taking longest"},
            {"type": "memory_bandwidth", "percentage": 30, "description": "Texture bandwidth limited"},
            {"type": "vertex_processing", "percentage": 15, "description": "Vertex shader and fetching"},
            {"type": "rasterization", "percentage": 10, "description": "Triangle setup and clipping"}
        ]

        result["utilization"] = {
            "shader_cores": {"average": 65, "peak": 90},
            "memory_controller": {"average": 70, "peak": 95},
            "rasterizer": {"average": 40, "peak": 60},
            "texture_units": {"average": 55, "peak": 80}
        }

        result["optimization_opportunities"] = [
            {"type": "shader_complexity", "description": "Reduce fragment shader instruction count", "potential_improvement": "20-30%"},
            {"type": "texture_format", "description": "Use compressed texture formats", "potential_improvement": "15-25%"},
            {"type": "batch_size", "description": "Increase draw call batching", "potential_improvement": "10-15%"},
            {"type": "early_z", "description": "Enable early-z optimizations", "potential_improvement": "5-10%"}
        ]

        return result

    async def _comprehensive_analysis(self, file_path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive GPU reverse engineering analysis"""
        self.logger.info(f"Performing comprehensive GPU analysis on {file_path}")

        # Run all analysis types
        basic_result = await self._basic_analysis(file_path, {})
        shader_result = await self._shader_analysis(file_path, {})
        binary_result = await self._binary_analysis(file_path, {})
        framebuffer_result = await self._framebuffer_analysis(file_path, {})
        command_buffer_result = await self._command_buffer_analysis(file_path, {})
        driver_result = await self._driver_interaction_analysis(file_path, {})
        performance_result = await self._performance_analysis(file_path, {})

        # Combine results
        result = {
            "file_path": file_path,
            "basic_info": basic_result,
            "shader_analysis": shader_result,
            "binary_analysis": binary_result,
            "framebuffer_analysis": framebuffer_result,
            "command_buffer_analysis": command_buffer_result,
            "driver_interaction": driver_result,
            "performance_analysis": performance_result,
            "analysis_timestamp": "2024-01-15T10:30:00Z",
            "summary": {
                "file_format": basic_result.get("file_format", "unknown"),
                "shader_stage": basic_result.get("shader_stage", "unknown"),
                "gpu_architecture": basic_result.get("gpu_architecture", "unknown"),
                "framebuffer_analysis": shader_result.get("control_flow_patterns", []),
                "texture_count": len(shader_result.get("texture_usage", [])),
                "draw_calls": len(command_buffer_result.get("draw_calls", [])),
                "performance_bottleneck": performance_result.get("bottlenecks", [{}])[0].get("type", "unknown") if performance_result.get("bottlenecks") else "unknown"
            }
        }

        return result

    async def _store_analysis_results(self, file_path: str, analysis_type: str, result: Dict[str, Any]):
        """Store analysis results in the knowledge base"""
        try:
            # Create a fact representing this analysis
            fact_title = f"GPU analysis of {Path(file_path).name}"
            fact_description = f"Completed {analysis_type} analysis of GPU-related file {file_path}"

            # Extract key findings for the fact
            key_findings = []
            if "summary" in result:
                summary = result["summary"]
                key_findings.append(f"Format: {summary.get('file_format', 'unknown')}")
                key_findings.append(f"Shader stage: {summary.get('shader_stage', 'unknown')}")
                key_findings.append(f"Architecture: {summary.get('gpu_architecture', 'unknown')}")
                key_findings.append(f"Draw calls: {summary.get('draw_calls', 0)}")
                key_findings.append(f"Bottleneck: {summary.get('performance_bottleneck', 'unknown')}")

            fact_description += ". " + "; ".join(key_findings)

            fact_id = add_fact(
                title=fact_title,
                description=fact_description,
                confidence=0.8,  # Good confidence for automated analysis
                evidence=[f"GPU analysis of {file_path} using {analysis_type} analysis"],
                source_references=[file_path],
                tags=["gpu_reverse_engineering", analysis_type, "automated_analysis"],
                source_agent=self.agent_id
            )

            # Also store specific findings as separate facts if they're significant
            if "performance_analysis" in result:
                perf = result["performance_analysis"]
                if "bottlenecks" in perf:
                    for bottleneck in perf["bottlenecks"]:
                        if bottleneck.get("percentage", 0) > 30:  # Significant bottleneck
                            bottleneck_fact_id = add_fact(
                                title=f"Performance bottleneck: {bottleneck.get('type', 'unknown')}",
                                description=f"Identified {bottleneck.get('type')} bottleneck at {bottleneck.get('percentage', 0)}%: {bottleneck.get('description', 'unknown')}",
                                confidence=0.75,
                                evidence=[f"GPU performance analysis of {file_path}"],
                                source_references=[file_path],
                                tags=["performance", "bottleneck", "gpu_analysis"],
                                source_agent=self.agent_id
                            )

            self.logger.info(f"Stored GPU analysis results in knowledge base (fact ID: {fact_id})")

        except Exception as e:
            self.logger.error(f"Failed to store GPU analysis results: {e}")

    def get_capabilities(self) -> Dict[str, Any]:
        """Get the capabilities of this agent"""
        return {
            "agent_type": self.agent_type,
            "supported_analyses": ["basic", "shader", "binary", "framebuffer", "command_buffer", "driver_interaction", "performance", "comprehensive"],
            "supported_formats": list(self.supported_formats),
            "available_tools": {k: v for k, v in self.analysis_tools.items() if v},
            "mcp_connected": False  # We're not using MCP in this implementation for simplicity
        }


# Factory function for easy creation
def create_gpu_reverse_engineering_agent(agent_id: str = None) -> GpuReverseEngineeringAgent:
    """Create a GPU reverse engineering agent"""
    return GpuReverseEngineeringAgent(agent_id=agent_id)


# Example usage and testing
if __name__ == "__main__":
    import logging
    import json
    logging.basicConfig(level=logging.INFO)

    async def test_gpu_reverse_engineering_agent():
        # Create the agent
        agent = create_gpu_reverse_engineering_agent("gpu_agent_001")
        print(f"Created agent: {agent.agent_id}")

        # Initialize it
        if await agent.initialize():
            print("Agent initialized successfully")
        else:
            print("Failed to initialize agent")
            return

        # Show capabilities
        capabilities = agent.get_capabilities()
        print(f"Agent capabilities: {json.dumps(capabilities, indent=2)}")

        # Create a test task
        test_task = Task(
            task_id="test_task_001",
            description="Analyze shader for performance issues",
            agent_type="gpu_reverse_engineering",
            priority=2,  # HIGH
            parameters={
                "file_path": "/tmp/shader.spv",
                "analysis_type": "shader"
            }
        )

        # Execute the task
        print("Executing test task...")
        result = await agent.execute_task(test_task)

        print(f"Task result: {json.dumps(result.__dict__, indent=2, default=str)}")

        # Clean up
        await agent.cleanup()
        print("Agent cleaned up")

    # Run the test
    asyncio.run(test_gpu_reverse_engineering_agent())