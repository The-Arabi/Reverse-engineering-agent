"""
Agent Orchestrator for the Reverse Engineering Lab
Manages agents, assigns tasks, tracks progress, and facilitates collaboration.
Phase 3: Self-critique loops, multi-agent debate, confidence scoring, token budgets.
Phase 6: Full mission execution with objective decomposition, dependency resolution,
         pause/resume/cancel, conflict detection, and automatic debate.
"""

import asyncio
import os
import uuid
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
import json
from collections import defaultdict, deque

# Import our base classes
from agents.base_agent import BaseAgent, AgentStatus, AgentPriority, Task, AgentResult
from knowledge_base import KnowledgeBase, add_fact, add_hypothesis, add_experiment, kb

# Agent type → (module_name, class_name) mapping for dynamic loading
_AGENT_MODULE_MAP: Dict[str, Tuple[str, str]] = {
    "binary": ("agents.binary_analysis_agent", "BinaryAnalysisAgent"),
    "firmware": ("agents.firmware_analysis_agent", "FirmwareAnalysisAgent"),
    "network": ("agents.networking_agent", "NetworkingAgent"),
    "cpu": ("agents.cpu_analysis_agent", "CpuAnalysisAgent"),
    "kernel": ("agents.os_kernel_agent", "OsKernelAgent"),
}


class MissionStatus(Enum):
    """Status of a research mission"""
    PLANNING = "planning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Priority(Enum):
    """Task priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class ResearchObjective:
    """Defines a research goal or objective"""
    id: str
    title: str
    description: str
    priority: Priority
    status: str  # pending, in_progress, completed, blocked
    assigned_agents: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)  # IDs of other objectives
    results: List[str] = field(default_factory=list)  # IDs of knowledge items
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Mission:
    """Represents a research mission or investigation"""
    id: str
    title: str
    description: str
    status: MissionStatus
    objectives: List[ResearchObjective] = field(default_factory=list)
    agents: Dict[str, BaseAgent] = field(default_factory=dict)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    created_by: str = "system"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AgentManager:
    """Manages registration and lifecycle of agents"""

    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.agent_types: Dict[str, type] = {}
        self.logger = logging.getLogger("agent_manager")

    def register_agent_type(self, agent_type: str, agent_class: type):
        """Register an agent type for instantiation"""
        self.agent_types[agent_type] = agent_class
        self.logger.info(f"Registered agent type: {agent_type}")

    def register_agent(self, agent: BaseAgent):
        """Register an agent instance"""
        self.agents[agent.agent_id] = agent
        self.logger.info(f"Registered agent: {agent.agent_id} ({agent.name})")

    def unregister_agent(self, agent_id: str):
        """Remove an agent from management"""
        if agent_id in self.agents:
            agent = self.agents.pop(agent_id)
            self.logger.info(f"Unregistered agent: {agent.agent_id} ({agent.name})")

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get an agent by ID"""
        return self.agents.get(agent_id)

    def get_agents_by_type(self, agent_type: str) -> List[BaseAgent]:
        """Get all agents of a specific type"""
        return [agent for agent in self.agents.values()
                if agent.agent_type == agent_type]

    def get_available_agents(self) -> List[BaseAgent]:
        """Get all agents that are idle and available for work"""
        return [agent for agent in self.agents.values()
                if agent.status == AgentStatus.IDLE]

    def get_busy_agents(self) -> List[BaseAgent]:
        """Get all agents that are currently busy"""
        return [agent for agent in self.agents.values()
                if agent.status in [AgentStatus.BUSY, AgentStatus.PROCESSING]]

    async def shutdown_all_agents(self):
        """Shutdown all managed agents"""
        shutdown_tasks = []
        for agent in self.agents.values():
            if agent.status != AgentStatus.SHUTDOWN:
                shutdown_tasks.append(agent.shutdown())

        if shutdown_tasks:
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)

        self.logger.info("All agents shutdown")


class TaskScheduler:
    """Tasks and assigns work to agents"""

    def __init__(self, agent_manager: AgentManager, knowledge_base: KnowledgeBase):
        self.agent_manager = agent_manager
        self.kb = knowledge_base
        self.logger = logging.getLogger("task_scheduler")
        self.task_queue: deque = deque()
        self.priority_queues: Dict[Priority, deque] = {
            Priority.CRITICAL: deque(),
            Priority.HIGH: deque(),
            Priority.MEDIUM: deque(),
            Priority.LOW: deque()
        }
        self.completed_tasks: List[Task] = []
        self.failed_tasks: List[Task] = []

    def add_task(self, task: Task):
        """Add a task to the appropriate priority queue"""
        self.priority_queues[task.priority].append(task)
        self.logger.debug(f"Added task {task.task_id} ({task.description}) to {task.priority.name} queue")

    def add_tasks(self, tasks: List[Task]):
        """Add multiple tasks"""
        for task in tasks:
            self.add_task(task)

    def get_next_task(self) -> Optional[Task]:
        """Get the next highest priority task"""
        # Check queues in priority order
        for priority in [Priority.CRITICAL, Priority.HIGH, Priority.MEDIUM, Priority.LOW]:
            if self.priority_queues[priority]:
                return self.priority_queues[priority].popleft()
        return None

    async def assign_task_to_agent(self, task: Task, agent_id: str = None) -> Optional[AgentResult]:
        """Assign a task to a specific agent or find an available one"""
        target_agent = None

        if agent_id:
            # Assign to specific agent
            target_agent = self.agent_manager.get_agent(agent_id)
            if not target_agent:
                self.logger.error(f"Agent {agent_id} not found")
                return None
        else:
            # Find best available agent
            # For now, just use the first available agent
            # In a more sophisticated system, we'd match agent capabilities to task requirements
            available_agents = self.agent_manager.get_available_agents()
            if not available_agents:
                self.logger.warning("No available agents for task assignment")
                return None
            target_agent = available_agents[0]

        if not target_agent.is_available():
            self.logger.warning(f"Target agent {target_agent.agent_id} is not available")
            return None

        self.logger.info(f"Assigning task {task.task_id} to agent {target_agent.agent_id}")
        return await target_agent.execute_task(task)

    async def process_task_queue(self, max_concurrent: int = 5):
        """Process tasks from the queue using available agents"""
        active_tasks = {}

        while True:
            # Check for completed tasks
            done_tasks = []
            for task_id, (task, agent_id, future) in list(active_tasks.items()):
                if future.done():
                    try:
                        result = await future
                        if result.status == "completed":
                            self.completed_tasks.append(task)
                            self.logger.info(f"Task {task.task_id} completed successfully")
                        else:
                            self.failed_tasks.append(task)
                            self.logger.warning(f"Task {task.task_id} failed: {result.error}")
                    except Exception as e:
                        self.failed_tasks.append(task)
                        self.logger.error(f"Task {task.task_id} failed with exception: {e}")

                    # Mark agent as idle
                    agent = self.agent_manager.get_agent(agent_id)
                    if agent:
                        await agent.complete_current_task()
                    done_tasks.append(task_id)

            # Clean up completed tasks
            for task_id in done_tasks:
                del active_tasks[task_id]

            # Assign new tasks if we have capacity
            while len(active_tasks) < max_concurrent:
                task = self.get_next_task()
                if not task:
                    break  # No more tasks

                # Find an available agent
                available_agents = self.agent_manager.get_available_agents()
                if not available_agents:
                    # Put the task back and wait
                    self.priority_queues[task.priority].appendleft(task)
                    break

                agent = available_agents[0]
                if not agent.is_available():
                    # Put the task back and wait
                    self.priority_queues[task.priority].appendleft(task)
                    break

                # Assign task
                self.logger.info(f"Assigning task {task.task_id} to agent {agent.agent_id}")
                await agent.start_task(task)
                future = asyncio.create_task(agent.execute_task(task))
                active_tasks[task.task_id] = (task, agent.agent_id, future)

            # If no active tasks and no pending tasks, we're done
            if not active_tasks and not any(self.priority_queues[p] for p in self.priority_queues):
                break

            # Wait a bit before checking again
            await asyncio.sleep(0.1)

        # Wait for any remaining tasks to complete
        if active_tasks:
            remaining_futures = [future for _, _, future in active_tasks.values()]
            await asyncio.gather(*remaining_futures, return_exceptions=True)


class ResearchOrchestrator:
    """Main orchestrator that coordinates research missions and agents.
    
    Phase 3 additions:
    - Self-critique loop: after task completion, runs critique and optionally re-analyzes
    - Multi-agent debate: facilitates structured debate between agents
    - Confidence scoring: computes composite confidence from tool/LLM/critique
    - Token budgets: tracks and limits LLM token consumption
    
    Phase 4 additions:
    - Metrics collection via monitoring.MetricsCollector
    """

    def __init__(self):
        self.agent_manager = AgentManager()
        self.task_scheduler = TaskScheduler(self.agent_manager, kb)
        self.knowledge_base = kb
        self.missions: Dict[str, Mission] = {}
        self.active_mission: Optional[Mission] = None
        self.logger = logging.getLogger("research_orchestrator")
        self._running = False

        # Phase 3: token budget, debate, critique
        self._token_budget_manager: Optional[Any] = None
        self._debate_system: Optional[Any] = None
        self._self_critique: Optional[Any] = None
        self._llm_client: Optional[Any] = None
        self._debate_results: List[Dict[str, Any]] = []
        self._task_results: Dict[str, AgentResult] = {}
        self._reanalysis_counts: Dict[str, int] = {}
        self._init_phase3()

        # Phase 4: monitoring
        self._metrics = None
        self._init_monitoring()

        # Phase 6: mission execution tracking
        self._mission_execution_tasks: Dict[str, asyncio.Task] = {}
        self._mission_pause_events: Dict[str, asyncio.Event] = {}
        self._mission_results: Dict[str, List[AgentResult]] = {}

    def register_agent_type(self, agent_type: str, agent_class: type):
        """Register an agent type"""
        self.agent_manager.register_agent_type(agent_type, agent_class)

    def create_mission(self, title: str, description: str, **kwargs) -> str:
        """Create a new research mission"""
        mission_id = str(uuid.uuid4())
        mission = Mission(
            id=mission_id,
            title=title,
            description=description,
            status=MissionStatus.PLANNING,
            **kwargs
        )
        self.missions[mission_id] = mission
        self.logger.info(f"Created mission {mission_id}: {title}")
        if self._metrics:
            self._metrics.record_mission_event("created")
            self._metrics.gauge_set("total_missions_created", float(len(self.missions)))
        return mission_id

    def set_active_mission(self, mission_id: str):
        """Set the currently active mission"""
        if mission_id not in self.missions:
            raise ValueError(f"Mission {mission_id} not found")
        self.active_mission = self.missions[mission_id]
        self.logger.info(f"Set active mission to {mission_id}")

    def add_objective_to_mission(self, mission_id: str, objective: ResearchObjective):
        """Add an objective to a mission"""
        if mission_id not in self.missions:
            raise ValueError(f"Mission {mission_id} not found")
        mission = self.missions[mission_id]
        mission.objectives.append(objective)
        self.logger.info(f"Added objective {objective.id} to mission {mission_id}")

    def assign_agent_to_mission(self, mission_id: str, agent: BaseAgent):
        """Assign an agent to a mission"""
        if mission_id not in self.missions:
            raise ValueError(f"Mission {mission_id} not found")
        mission = self.missions[mission_id]
        mission.agents[agent.agent_id] = agent
        self.agent_manager.register_agent(agent)
        self.logger.info(f"Assigned agent {agent.agent_id} to mission {mission_id}")

    async def start_mission(self, mission_id: str):
        """Start executing a mission.

        Validates the mission, transitions to ACTIVE, then spawns a background
        task that decomposes objectives into agent tasks, executes them with
        self-critique, stores results in the KB, detects conflicts, and
        facilitates debate when needed.

        Returns immediately after spawning the background task. Use
        ``get_mission_status`` or ``re_mission_detail`` to poll progress.
        """
        if mission_id not in self.missions:
            raise ValueError(f"Mission {mission_id} not found")

        mission = self.missions[mission_id]
        if mission.status != MissionStatus.PLANNING:
            raise ValueError(
                f"Mission {mission_id} is not in planning state "
                f"(current: {mission.status.value})"
            )

        self.logger.info(f"Starting mission {mission_id}: {mission.title}")
        mission.status = MissionStatus.ACTIVE
        mission.start_time = datetime.now().isoformat()
        self.set_active_mission(mission_id)

        # Create pause/resume event for this execution run
        pause_event = asyncio.Event()
        pause_event.set()  # starts unpaused
        self._mission_pause_events[mission_id] = pause_event

        # Initialize results storage
        self._mission_results[mission_id] = []

        if self._metrics:
            self._metrics.record_mission_event("started")
            self._metrics.gauge_set(
                "active_missions",
                float(len([m for m in self.missions.values()
                           if m.status == MissionStatus.ACTIVE])),
            )

        # Spawn background execution
        bg_task = asyncio.create_task(self._execute_mission(mission_id))
        self._mission_execution_tasks[mission_id] = bg_task
        bg_task.add_done_callback(
            lambda t, mid=mission_id: self._on_mission_task_done(mid, t)
        )

    def _on_mission_task_done(self, mission_id: str, task: asyncio.Task):
        """Callback when background mission task completes."""
        self._mission_execution_tasks.pop(mission_id, None)
        self._mission_pause_events.pop(mission_id, None)
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            self.logger.error(
                f"Mission {mission_id} background task failed: {exc}"
            )
            mission = self.missions.get(mission_id)
            if mission and mission.status == MissionStatus.ACTIVE:
                mission.status = MissionStatus.FAUSED
                mission.end_time = datetime.now().isoformat()
                mission.metadata["error"] = str(exc)

    # -----------------------------------------------------------------------
    # Phase 6: Mission execution engine
    # -----------------------------------------------------------------------

    async def _execute_mission(self, mission_id: str):
        """Core mission execution loop.

        1. Decompose objectives into Task objects
        2. Topologically sort by dependencies
        3. Execute each task with self-critique
        4. Check for pause/cancel between objectives
        5. Store results in knowledge base
        6. Detect conflicts and trigger debate
        7. Mark mission COMPLETED or FAILED
        """
        mission = self.missions.get(mission_id)
        if not mission:
            return

        objective_results: Dict[str, List[AgentResult]] = {}
        all_results: List[AgentResult] = []
        failed_count = 0
        completed_count = 0

        try:
            # --- Step 1: Decompose objectives into tasks ---
            task_plan = self._plan_objectives(mission)
            if not task_plan:
                # No objectives — complete immediately
                mission.status = MissionStatus.COMPLETED
                mission.end_time = datetime.now().isoformat()
                mission.metadata["completed_objectives"] = 0
                mission.metadata["total_objectives"] = 0
                self.logger.info(
                    f"Mission {mission_id} has no objectives, completing immediately"
                )
                return

            # --- Step 2: Execute tasks in dependency order ---
            for obj_id, tasks, objective in task_plan:
                # Check for pause
                await self._check_pause_cancel(mission_id)

                # Check if dependencies are met
                if not self._dependencies_met(mission, objective, objective_results):
                    self.logger.warning(
                        f"Skipping objective {objective.id} ({objective.title}): "
                        "dependencies not satisfied"
                    )
                    objective.status = "blocked"
                    continue

                objective.status = "in_progress"
                objective.updated_at = datetime.now().isoformat()

                for task in tasks:
                    # Check for pause/cancel before each task
                    await self._check_pause_cancel(mission_id)

                    self.logger.info(
                        f"Executing task {task.task_id} for objective "
                        f"{objective.id} ({objective.title})"
                    )

                    # Execute with self-critique
                    result = await self._execute_task_dynamically(task)

                    if result is None:
                        result = AgentResult(
                            task_id=task.task_id,
                            agent_id="unknown",
                            status="failed",
                            error="No agent available for task",
                        )

                    all_results.append(result)
                    self._mission_results[mission_id].append(result)

                    if result.status == "completed":
                        completed_count += 1
                        objective.results.append(result.task_id)
                        # Store in KB
                        await self._store_result_in_kb(result, mission_id, objective)
                    else:
                        failed_count += 1
                        self.logger.warning(
                            f"Task {task.task_id} failed: {result.error}"
                        )

                # Mark objective completed if any task succeeded
                if objective.results:
                    objective.status = "completed"
                else:
                    objective.status = "failed"
                objective.updated_at = datetime.now().isoformat()

                objective_results[obj_id] = [
                    r for r in all_results
                    if r.task_id in {t.task_id for t in tasks}
                ]

            # --- Step 3: Conflict detection and debate ---
            debate_summary = await self._detect_and_debate_conflicts(
                mission, all_results
            )
            if debate_summary:
                mission.metadata["debate"] = debate_summary

            # --- Step 4: Finalize mission ---
            total_objectives = len(mission.objectives)
            completed_objectives = sum(
                1 for o in mission.objectives if o.status == "completed"
            )

            if completed_objectives == total_objectives:
                mission.status = MissionStatus.COMPLETED
            elif completed_objectives > 0:
                # Partial completion
                mission.status = MissionStatus.COMPLETED
                mission.metadata["partial"] = True
            else:
                mission.status = MissionStatus.FAILED

            mission.end_time = datetime.now().isoformat()
            mission.metadata["completed_objectives"] = completed_objectives
            mission.metadata["total_objectives"] = total_objectives
            mission.metadata["tasks_completed"] = completed_count
            mission.metadata["tasks_failed"] = failed_count

            self.logger.info(
                f"Mission {mission_id} finished: {mission.status.value} "
                f"({completed_objectives}/{total_objectives} objectives, "
                f"{completed_count} tasks completed, {failed_count} failed)"
            )

        except asyncio.CancelledError:
            mission.status = MissionStatus.CANCELLED
            mission.end_time = datetime.now().isoformat()
            mission.metadata["cancelled_at"] = datetime.now().isoformat()
            self.logger.info(f"Mission {mission_id} was cancelled")

        except Exception as e:
            mission.status = MissionStatus.FAILED
            mission.end_time = datetime.now().isoformat()
            mission.metadata["error"] = str(e)
            self.logger.error(f"Mission {mission_id} failed with exception: {e}")

        finally:
            if self._metrics:
                self._metrics.record_mission_event(mission.status.value)
                self._metrics.gauge_set(
                    "active_missions",
                    float(len([m for m in self.missions.values()
                               if m.status == MissionStatus.ACTIVE])),
                )

    async def _check_pause_cancel(self, mission_id: str):
        """Block if mission is paused; raise CancelledError if cancelled."""
        mission = self.missions.get(mission_id)
        if not mission:
            return

        if mission.status == MissionStatus.CANCELLED:
            raise asyncio.CancelledError(f"Mission {mission_id} cancelled")

        if mission.status == MissionStatus.PAUSED:
            self.logger.info(f"Mission {mission_id} paused, waiting...")
            pause_event = self._mission_pause_events.get(mission_id)
            if pause_event:
                # Wait until resumed or cancelled
                while mission.status == MissionStatus.PAUSED:
                    try:
                        await asyncio.wait_for(pause_event.wait(), timeout=1.0)
                    except asyncio.TimeoutError:
                        # Re-check status (could have been cancelled while paused)
                        if mission.status == MissionStatus.CANCELLED:
                            raise asyncio.CancelledError(
                                f"Mission {mission_id} cancelled while paused"
                            )
                self.logger.info(f"Mission {mission_id} resumed")
            else:
                # No event — just spin until status changes
                while mission.status == MissionStatus.PAUSED:
                    await asyncio.sleep(0.5)

    async def _execute_task_dynamically(self, task: Task) -> Optional[AgentResult]:
        """Execute a task by dynamically loading the appropriate agent.

        Similar to how re_analyze works: imports the agent module, creates an
        instance, runs initialize → execute_task → cleanup. Then runs
        orchestrator-level self-critique on the result.
        """
        # Extract agent type from task (e.g. "binary_analysis" → "binary")
        agent_type_raw = task.agent_type.replace("_analysis", "")
        agent_spec = _AGENT_MODULE_MAP.get(agent_type_raw)

        if not agent_spec:
            return AgentResult(
                task_id=task.task_id,
                agent_id="unknown",
                status="failed",
                error=f"Unknown agent type: {task.agent_type} (resolved: {agent_type_raw})",
            )

        mod_name, class_name = agent_spec
        try:
            mod = __import__(mod_name, fromlist=[class_name])
            agent_cls = getattr(mod, class_name)
        except (ImportError, AttributeError) as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id="unknown",
                status="failed",
                error=f"Failed to load agent {agent_type_raw}: {e}",
            )

        agent_id = f"mission_{task.task_id}"
        agent = agent_cls(agent_id)

        try:
            await agent.initialize()
            result = await agent.execute_task(task)

            if result is None:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=agent_id,
                    status="failed",
                    error="Agent returned None",
                )

            # Run orchestrator-level critique
            result = await self._run_orchestrator_critique(task, result)
            self._task_results[task.task_id] = result
            return result

        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=agent_id,
                status="failed",
                error=f"Agent execution failed: {e}",
            )
        finally:
            try:
                await agent.cleanup()
            except Exception:
                pass

    def _plan_objectives(
        self, mission: Mission
    ) -> List[Tuple[str, List[Task], ResearchObjective]]:
        """Decompose objectives into executable tasks, respecting dependencies.

        Returns a list of (objective_id, tasks, objective) tuples sorted by
        dependency order (topological sort).
        """
        if not mission.objectives:
            return []

        # Topological sort by dependencies
        ordered = self._topological_sort_objectives(mission.objectives)

        plan = []
        file_path = mission.metadata.get("file_path", "")

        for objective in ordered:
            tasks = self._create_tasks_for_objective(
                objective, mission, file_path
            )
            if tasks:
                plan.append((objective.id, tasks, objective))

        return plan

    def _topological_sort_objectives(
        self, objectives: List[ResearchObjective]
    ) -> List[ResearchObjective]:
        """Sort objectives so dependencies come first."""
        obj_map = {o.id: o for o in objectives}
        visited: Set[str] = set()
        sorted_list: List[ResearchObjective] = []

        def visit(obj_id: str):
            if obj_id in visited:
                return
            visited.add(obj_id)
            obj = obj_map.get(obj_id)
            if obj is None:
                return
            for dep_id in obj.dependencies:
                if dep_id in obj_map:
                    visit(dep_id)
            sorted_list.append(obj)

        for obj in objectives:
            visit(obj.id)

        return sorted_list

    def _create_tasks_for_objective(
        self,
        objective: ResearchObjective,
        mission: Mission,
        default_file_path: str,
    ) -> List[Task]:
        """Create Task objects for a single objective.

        Uses ``assigned_agents`` to determine agent types.  Falls back to
        auto-detection from the objective description when no agents are
        explicitly assigned.
        """
        agent_types: List[str] = []

        if objective.assigned_agents:
            for agent_ref in objective.assigned_agents:
                # Normalize: "binary_analysis_agent" → "binary"
                normalized = agent_ref.lower().replace("_analysis", "").replace("_agent", "")
                if normalized in _AGENT_MODULE_MAP:
                    agent_types.append(normalized)
                else:
                    # Try direct match
                    agent_types.append(normalized)

        if not agent_types:
            # Auto-detect from description
            agent_types = self._infer_agent_types(objective.description)

        if not agent_types:
            # Default to binary analysis
            agent_types = ["binary"]

        # Resolve file_path: objective metadata > mission metadata > description
        file_path = (
            objective.results  # results field doubles as misc storage
            and ""
        ) or ""
        # Try metadata on the objective itself
        file_path = getattr(objective, 'metadata', {}).get("file_path", "") if hasattr(objective, 'metadata') else ""
        if not file_path:
            file_path = mission.metadata.get("file_path", default_file_path)

        # Priority mapping
        priority_map = {
            Priority.CRITICAL: AgentPriority.CRITICAL,
            Priority.HIGH: AgentPriority.HIGH,
            Priority.MEDIUM: AgentPriority.MEDIUM,
            Priority.LOW: AgentPriority.LOW,
        }
        agent_priority = priority_map.get(objective.priority, AgentPriority.MEDIUM)

        tasks = []
        for agent_type in agent_types:
            task_id = f"mission_{mission.id[:8]}_obj_{objective.id[:8]}_{agent_type}_{uuid.uuid4().hex[:6]}"
            task = Task(
                task_id=task_id,
                description=f"[{objective.title}] {objective.description}",
                agent_type=f"{agent_type}_analysis",
                priority=agent_priority,
                parameters={
                    "file_path": file_path,
                    "analysis_type": "comprehensive",
                    "objective_id": objective.id,
                    "objective_title": objective.title,
                    "mission_id": mission.id,
                },
            )
            tasks.append(task)

        return tasks

    def _infer_agent_types(self, description: str) -> List[str]:
        """Infer agent types from a description string."""
        desc_lower = description.lower()
        types = []

        keyword_map = {
            "binary": ["binary", "executable", "elf", "pe ", "mach-o", "disassembl", "decompil"],
            "firmware": ["firmware", "iot", "embedded", "router", "binwalk", "squashfs", "flash"],
            "network": ["network", "packet", "pcap", "traffic", "protocol", "dns", "http"],
            "cpu": ["cpu", "register", "instruction", "assembly", "asm", "opcode"],
            "kernel": ["kernel", "module", "driver", ".ko", "syscall", "strace", "os "],
        }

        for agent_type, keywords in keyword_map.items():
            if any(kw in desc_lower for kw in keywords):
                types.append(agent_type)

        return types

    def _dependencies_met(
        self,
        mission: Mission,
        objective: ResearchObjective,
        completed_results: Dict[str, List[AgentResult]],
    ) -> bool:
        """Check if all dependencies of an objective are satisfied."""
        if not objective.dependencies:
            return True

        obj_map = {o.id: o for o in mission.objectives}
        for dep_id in objective.dependencies:
            dep_obj = obj_map.get(dep_id)
            if dep_obj is None:
                # Dependency not found — treat as satisfied
                continue
            if dep_obj.status not in ("completed",):
                return False

        return True

    async def _store_result_in_kb(
        self,
        result: AgentResult,
        mission_id: str,
        objective: ResearchObjective,
    ):
        """Store an agent result in the knowledge base as a fact."""
        if not result.result:
            return

        try:
            # Build a summary for the KB fact
            if isinstance(result.result, dict):
                summary = result.result.get("summary", {})
                if isinstance(summary, dict):
                    desc_parts = [f"{k}: {v}" for k, v in list(summary.items())[:5]]
                    description = "; ".join(desc_parts)
                else:
                    description = str(summary)[:500]
            else:
                description = str(result.result)[:500]

            tags = [
                "mission",
                mission_id[:8],
                objective.id[:8],
                result.agent_id,
            ]

            # Add agent-specific tags
            if result.tools_used:
                tags.extend(result.tools_used[:3])

            fact_id = await add_fact(
                title=f"[{objective.title}] {result.agent_id} analysis",
                description=description,
                confidence=result.confidence_score,
                evidence=json.dumps({
                    "task_id": result.task_id,
                    "agent_id": result.agent_id,
                    "tools_used": result.tools_used,
                    "reanalysis_count": result.reanalysis_count,
                }, default=str),
                tags=tags,
            )

            if fact_id:
                objective.results.append(fact_id)
                self.logger.debug(
                    f"Stored result {result.task_id} in KB as fact {fact_id}"
                )

        except Exception as e:
            self.logger.warning(f"Failed to store result in KB: {e}")

    async def _detect_and_debate_conflicts(
        self, mission: Mission, results: List[AgentResult]
    ) -> Optional[Dict[str, Any]]:
        """Compare results across agents and trigger debate on conflicts."""
        if len(results) < 2:
            return None

        try:
            from config.settings import DEBATE_ENABLED
            if not DEBATE_ENABLED:
                return None
        except ImportError:
            return None

        # Group results by objective
        obj_results: Dict[str, List[AgentResult]] = defaultdict(list)
        for r in results:
            for key, val in r.result.items() if isinstance(r.result, dict) else []:
                pass
            # Use the task's objective_id parameter
            obj_id = ""
            # We can reconstruct this from the task_id pattern
            # But simpler: just use the agent results directly
            obj_results["all"].append(r)

        # Check for low-confidence results that might conflict
        low_confidence = [
            r for r in results
            if r.confidence_score < 0.5 and r.status == "completed"
        ]

        if len(low_confidence) >= 2:
            # Multiple low-confidence results — potential conflict
            topic = f"Conflicting analysis results in mission: {mission.title}"
            agent_results_dict = {
                r.agent_id: r for r in low_confidence[:5]  # limit to 5
            }
            try:
                debate_result = await self.facilitate_debate(
                    topic=topic,
                    agent_results=agent_results_dict,
                )
                if debate_result:
                    return {
                        "topic": topic,
                        "triggered_by": "low_confidence_conflict",
                        "result": debate_result,
                    }
            except Exception as e:
                self.logger.warning(f"Debate failed: {e}")

        # Check for results with very different key_findings
        findings_groups: Dict[str, List[AgentResult]] = defaultdict(list)
        for r in results:
            if r.status != "completed" or not r.llm_analysis:
                continue
            key_findings = r.llm_analysis.get("key_findings", [])
            if key_findings:
                # Use first finding as a grouping key
                first_finding = str(key_findings[0])[:50].lower()
                # Simple fingerprint
                fingerprint = " ".join(sorted(first_finding.split()[:3]))
                findings_groups[fingerprint].append(r)

        # If we have multiple distinct finding groups, there's a disagreement
        if len(findings_groups) > 1:
            # Pick the two most-populated groups
            sorted_groups = sorted(
                findings_groups.values(), key=lambda g: len(g), reverse=True
            )
            if len(sorted_groups) >= 2 and len(sorted_groups[0]) >= 1 and len(sorted_groups[1]) >= 1:
                topic = f"Disagreement in mission: {mission.title}"
                agent_results_dict = {}
                for r in sorted_groups[0][:2] + sorted_groups[1][:2]:
                    agent_results_dict[r.agent_id] = r

                try:
                    debate_result = await self.facilitate_debate(
                        topic=topic,
                        agent_results=agent_results_dict,
                    )
                    if debate_result:
                        return {
                            "topic": topic,
                            "triggered_by": "findings_disagreement",
                            "result": debate_result,
                        }
                except Exception as e:
                    self.logger.warning(f"Debate failed: {e}")

        return None

    async def pause_mission(self, mission_id: str):
        """Pause a running mission.

        The background execution task will stop between objectives/tasks.
        """
        if mission_id not in self.missions:
            raise ValueError(f"Mission {mission_id} not found")
        mission = self.missions[mission_id]
        if mission.status != MissionStatus.ACTIVE:
            raise ValueError(
                f"Mission {mission_id} is not active (current: {mission.status.value})"
            )
        mission.status = MissionStatus.PAUSED
        pause_event = self._mission_pause_events.get(mission_id)
        if pause_event:
            pause_event.clear()  # signal pause
        self.logger.info(f"Paused mission {mission_id}")
        if self._metrics:
            self._metrics.record_mission_event("paused")

    async def resume_mission(self, mission_id: str):
        """Resume a paused mission."""
        if mission_id not in self.missions:
            raise ValueError(f"Mission {mission_id} not found")
        mission = self.missions[mission_id]
        if mission.status != MissionStatus.PAUSED:
            raise ValueError(
                f"Mission {mission_id} is not paused (current: {mission.status.value})"
            )
        mission.status = MissionStatus.ACTIVE
        pause_event = self._mission_pause_events.get(mission_id)
        if pause_event:
            pause_event.set()  # signal resume
        self.logger.info(f"Resumed mission {mission_id}")
        if self._metrics:
            self._metrics.record_mission_event("resumed")

    async def cancel_mission(self, mission_id: str):
        """Cancel a running or paused mission.

        Sets the status to CANCELLED. The background task will pick this up
        at the next pause/cancel check point and terminate.
        """
        if mission_id not in self.missions:
            raise ValueError(f"Mission {mission_id} not found")
        mission = self.missions[mission_id]
        if mission.status in [MissionStatus.COMPLETED, MissionStatus.FAILED, MissionStatus.CANCELLED]:
            raise ValueError(
                f"Cannot cancel mission {mission_id} in {mission.status.value} state"
            )
        mission.status = MissionStatus.CANCELLED
        mission.end_time = datetime.now().isoformat()
        # Wake up the task if it's paused so it can see the cancel
        pause_event = self._mission_pause_events.get(mission_id)
        if pause_event:
            pause_event.set()
        # Also cancel the asyncio task directly for immediate effect
        bg_task = self._mission_execution_tasks.get(mission_id)
        if bg_task and not bg_task.done():
            bg_task.cancel()
        self.logger.info(f"Cancelled mission {mission_id}")
        if self._metrics:
            self._metrics.record_mission_event("cancelled")

    async def get_mission_progress(self, mission_id: str) -> Dict[str, Any]:
        """Get detailed progress information for a running mission."""
        mission = self.missions.get(mission_id)
        if not mission:
            return {"error": f"Mission {mission_id} not found"}

        results = self._mission_results.get(mission_id, [])
        completed = sum(1 for r in results if r.status == "completed")
        failed = sum(1 for r in results if r.status == "failed")

        objective_progress = []
        for obj in mission.objectives:
            objective_progress.append({
                "id": obj.id,
                "title": obj.title,
                "status": obj.status,
                "results_count": len(obj.results),
            })

        return {
            "mission_id": mission_id,
            "title": mission.title,
            "status": mission.status.value,
            "start_time": mission.start_time,
            "end_time": mission.end_time,
            "tasks_completed": completed,
            "tasks_failed": failed,
            "tasks_total": len(results),
            "objectives": objective_progress,
            "debate_count": len([
                d for d in self._debate_results
                if mission_id[:8] in str(d)
            ]),
            "is_running": mission_id in self._mission_execution_tasks,
        }

    def get_mission_status(self, mission_id: str) -> Optional[Mission]:
        """Get the status of a mission"""
        return self.missions.get(mission_id)

    def list_missions(self) -> List[Mission]:
        """List all missions"""
        return list(self.missions.values())

    async def start(self):
        """Start the orchestrator"""
        self._running = True
        self.logger.info("Research orchestrator started")

        # Start the task scheduler in the background
        asyncio.create_task(self.task_scheduler.process_task_queue())

    async def stop(self):
        """Stop the orchestrator"""
        self._running = False
        await self.agent_manager.shutdown_all_agents()
        self.logger.info("Research orchestrator stopped")

    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        status = {
            "orchestrator_running": self._running,
            "active_mission": self.active_mission.id if self.active_mission else None,
            "total_missions": len(self.missions),
            "missions_by_status": {
                status.value: len([m for m in self.missions.values() if m.status == status])
                for status in MissionStatus
            },
            "total_agents": len(self.agent_manager.agents),
            "available_agents": len(self.agent_manager.get_available_agents()),
            "busy_agents": len(self.agent_manager.get_busy_agents()),
            "knowledge_base_stats": self.knowledge_base.get_statistics(),
            "task_queue_stats": {
                "total_queued": sum(len(q) for q in self.task_scheduler.priority_queues.values()),
                "completed": len(self.task_scheduler.completed_tasks),
                "failed": len(self.task_scheduler.failed_tasks)
            },
        }
        # Phase 3: add budget and debate stats
        if self._token_budget_manager:
            status["token_budget"] = self._token_budget_manager.get_usage_summary(
                mission_id=self.active_mission.id if self.active_mission else None
            )
        status["debate_count"] = len(self._debate_results)
        status["total_reanalyses"] = sum(self._reanalysis_counts.values())
        status["monitoring_enabled"] = self._metrics is not None
        return status

    # -----------------------------------------------------------------------
    # Phase 3: Initialization helpers
    # -----------------------------------------------------------------------

    def _init_phase3(self):
        """Initialize Phase 3 components (token budget, debate, self-critique)."""
        # Token budget manager
        try:
            from config.settings import TOKEN_BUDGET_ENABLED
            if TOKEN_BUDGET_ENABLED:
                from token_budget import TokenBudgetManager
                self._token_budget_manager = TokenBudgetManager()
                self.logger.info("Token budget manager initialized")
        except Exception as e:
            self.logger.warning(f"Token budget manager not available: {e}")

        # LLM client (shared)
        try:
            from llm_client import get_llm_client
            self._llm_client = get_llm_client()
        except Exception as e:
            self.logger.warning(f"LLM client not available for orchestrator: {e}")

        # Self-critique
        try:
            from self_critique import SelfCritique
            self._self_critique = SelfCritique(llm_client=self._llm_client)
        except Exception as e:
            self.logger.warning(f"Self-critique not available: {e}")

        # Debate system
        try:
            from debate import MultiAgentDebate
            self._debate_system = MultiAgentDebate(llm_client=self._llm_client)
        except Exception as e:
            self.logger.warning(f"Debate system not available: {e}")

    # -----------------------------------------------------------------------
    # Phase 4: Monitoring initialization
    # -----------------------------------------------------------------------

    def _init_monitoring(self):
        """Initialize the metrics collector for observability."""
        try:
            from monitoring import get_metrics
            self._metrics = get_metrics()
            self._metrics.set_info("version", "4.0.0")
            self._metrics.set_info("environment", os.getenv("REVERSE_ENGINEERING_ENV", "development"))
            self.logger.info("Monitoring initialized")
        except Exception as e:
            self.logger.warning(f"Monitoring not available: {e}")

    # -----------------------------------------------------------------------
    # Phase 3: Self-critique loop
    # -----------------------------------------------------------------------

    async def _run_orchestrator_critique(
        self, task: Task, result: AgentResult
    ) -> AgentResult:
        """Run orchestrator-level self-critique on a task result.

        If critique score is below threshold, triggers re-analysis (up to max attempts).
        Updates the result with critique data and confidence score.
        """
        try:
            from config.settings import (
                CRITIQUE_ENABLED, CRITIQUE_CONFIDENCE_THRESHOLD,
                REANALYZE_ENABLED, REANALYZE_MAX_ATTEMPTS,
            )
        except ImportError:
            return result

        if not CRITIQUE_ENABLED or not self._self_critique:
            return result

        # Build tool output summary from reasoning trace
        tool_summary_parts = []
        for step in result.reasoning_trace:
            if step.get("tool"):
                tool_summary_parts.append(f"[{step['tool']}] {step.get('detail', '')}")
        tool_summary = "\n".join(tool_summary_parts) if tool_summary_parts else "No tool outputs"

        # Run critique
        try:
            critique_result = await self._self_critique.evaluate_analysis(
                agent_type=task.agent_type,
                tool_output_summary=tool_summary,
                analysis_result=result.result if isinstance(result.result, dict) else {"raw": str(result.result)[:2000]},
            )
            result.critique = critique_result.to_dict()
            result.add_reasoning_step(
                "orchestrator_critique",
                detail={"score": critique_result.score, "issues": len(critique_result.issues_found)},
            )
            if self._metrics:
                self._metrics.record_critique(
                    reanalysis=False,
                    score=critique_result.score,
                )
        except Exception as e:
            self.logger.warning(f"Orchestrator critique failed: {e}")
            return result

        # Compute confidence
        self._compute_result_confidence(result)

        # Re-analyze if needed
        if REANALYZE_ENABLED and result.confidence_score < CRITIQUE_CONFIDENCE_THRESHOLD:
            task_key = f"{task.task_id}_{task.agent_type}"
            current_attempts = self._reanalysis_counts.get(task_key, 0)
            if current_attempts < REANALYZE_MAX_ATTEMPTS:
                self._reanalysis_counts[task_key] = current_attempts + 1
                result.reanalysis_count = current_attempts + 1
                self.logger.info(
                    f"Re-analyzing task {task.task_id} "
                    f"(attempt {current_attempts + 1}/{REANALYZE_MAX_ATTEMPTS}, "
                    f"confidence={result.confidence_score:.2f})"
                )
                if self._metrics:
                    self._metrics.record_critique(reanalysis=True, score=result.confidence_score)
                # Re-execute the task
                agent = self.agent_manager.get_agent(result.agent_id)
                if agent and hasattr(agent, 'execute_task'):
                    try:
                        re_result = await agent.execute_task(task)
                        if re_result and re_result.status == "completed":
                            # Merge: keep the better result
                            if re_result.confidence_score > result.confidence_score:
                                re_result.reanalysis_count = current_attempts + 1
                                self._compute_result_confidence(re_result)
                                return re_result
                    except Exception as e:
                        self.logger.warning(f"Re-analysis failed: {e}")

        return result

    def _compute_result_confidence(self, result: AgentResult):
        """Compute composite confidence score for a result."""
        try:
            from config.settings import (
                CONFIDENCE_TOOL_WEIGHT, CONFIDENCE_LLM_WEIGHT,
                CONFIDENCE_CRITIQUE_WEIGHT,
            )
            result.compute_confidence(
                tool_weight=CONFIDENCE_TOOL_WEIGHT,
                llm_weight=CONFIDENCE_LLM_WEIGHT,
                critique_weight=CONFIDENCE_CRITIQUE_WEIGHT,
            )
        except Exception:
            result.compute_confidence()

    # -----------------------------------------------------------------------
    # Phase 3: Multi-agent debate
    # -----------------------------------------------------------------------

    async def facilitate_debate(
        self,
        topic: str,
        agent_results: Dict[str, AgentResult],
        max_rounds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Facilitate a multi-agent debate on a topic.

        Args:
            topic: The debate topic/question
            agent_results: Dict of agent_id -> AgentResult with analysis to debate
            max_rounds: Maximum debate rounds (default from config)

        Returns:
            DebateResult as dict, or None if debate cannot proceed
        """
        try:
            from config.settings import DEBATE_ENABLED, DEBATE_MAX_ROUNDS
        except ImportError:
            return None

        if not DEBATE_ENABLED:
            return None

        if max_rounds is None:
            max_rounds = DEBATE_MAX_ROUNDS

        # Build assertions from agent results
        assertions = []
        for agent_id, result in agent_results.items():
            if result.status != "completed" or not result.result:
                continue

            # Extract key assertion from result
            assertion_text = self._extract_assertion(result)
            if not assertion_text:
                continue

            agent = self.agent_manager.get_agent(agent_id)
            agent_name = agent.name if agent else agent_id
            agent_type = getattr(agent, 'agent_type', 'general')

            context_parts = [f"Confidence: {result.confidence_score:.2f}"]
            if result.llm_analysis:
                findings = result.llm_analysis.get("key_findings", [])
                if findings:
                    context_parts.append(f"Key findings: {', '.join(str(f) for f in findings[:3])}")
            if result.tools_used:
                context_parts.append(f"Tools used: {', '.join(result.tools_used)}")

            assertions.append({
                "assertion": assertion_text,
                "agent_id": agent_id,
                "agent_name": agent_name,
                "agent_type": agent_type,
                "context": "\n".join(context_parts),
            })

        if len(assertions) < 2:
            self.logger.info("Not enough assertions for debate (need >= 2)")
            return None

        # Run debate
        if self._debate_system:
            try:
                debate_result = await self._debate_system.run_full_debate(
                    topic=topic,
                    assertions=assertions,
                    max_rounds=max_rounds,
                )
            except Exception as e:
                self.logger.warning(f"LLM debate failed, falling back to offline: {e}")
                debate_result = self._debate_system.run_debate_offline(
                    topic=topic,
                    assertions=assertions,
                    max_rounds=max_rounds,
                )
        else:
            # No LLM available — use offline debate
            from debate import MultiAgentDebate
            offline_debate = MultiAgentDebate(llm_client=None)
            debate_result = offline_debate.run_debate_offline(
                topic=topic,
                assertions=assertions,
                max_rounds=max_rounds,
            )

        debate_dict = debate_result.to_dict()
        self._debate_results.append(debate_dict)
        self.logger.info(
            f"Debate completed: topic='{topic}', "
            f"consensus={debate_result.final_consensus}, "
            f"confidence={debate_result.final_confidence:.2f}"
        )
        if self._metrics:
            self._metrics.record_debate(
                consensus=debate_result.final_consensus,
                rounds=len(debate_result.rounds),
            )
        return debate_dict

    def _extract_assertion(self, result: AgentResult) -> str:
        """Extract a debatable assertion from an agent result."""
        if not result.result:
            return ""

        if isinstance(result.result, dict):
            # Try to get key_findings from LLM analysis
            if result.llm_analysis and "key_findings" in result.llm_analysis:
                findings = result.llm_analysis["key_findings"]
                if findings:
                    return findings[0] if isinstance(findings[0], str) else str(findings[0])

            # Try summary
            if "summary" in result.result:
                summary = result.result["summary"]
                if isinstance(summary, dict):
                    parts = [f"{k}: {v}" for k, v in list(summary.items())[:3]]
                    return "; ".join(parts)
                return str(summary)[:200]

            # Fallback to string representation
            return str(result.result)[:200]

        return str(result.result)[:200]

    # -----------------------------------------------------------------------
    # Phase 3: Enhanced task execution with critique loop
    # -----------------------------------------------------------------------

    async def execute_task_with_critique(
        self, task: Task, agent_id: Optional[str] = None
    ) -> Optional[AgentResult]:
        """Execute a task with self-critique loop and confidence scoring.

        This is the enhanced version of TaskScheduler.assign_task_to_agent
        that adds orchestrator-level critique and re-analysis.
        """
        result = await self.task_scheduler.assign_task_to_agent(task, agent_id)
        if result is None:
            return None

        # Store result for debate
        self._task_results[task.task_id] = result

        # Run orchestrator-level critique
        result = await self._run_orchestrator_critique(task, result)
        self._task_results[task.task_id] = result

        return result

    def get_debate_results(self) -> List[Dict[str, Any]]:
        """Get all debate results from this orchestrator session."""
        return self._debate_results.copy()

    def get_task_confidence(self, task_id: str) -> float:
        """Get the confidence score for a completed task."""
        result = self._task_results.get(task_id)
        if result:
            return result.confidence_score
        return 0.0


# Global orchestrator instance
orchestrator = ResearchOrchestrator()


# Convenience functions
def create_research_mission(title: str, description: str, **kwargs) -> str:
    """Convenience function to create a research mission"""
    return orchestrator.create_mission(title, description, **kwargs)


def start_research_mission(mission_id: str):
    """Convenience function to start a research mission"""
    asyncio.create_task(orchestrator.start_mission(mission_id))


if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(level=logging.INFO)

    async def main():
        # Start the orchestrator
        await orchestrator.start()

        # Create a sample mission
        mission_id = create_research_mission(
            title="GPU Reverse Engineering Investigation",
            description="Investigate unknown GPU device to understand its command structure and capabilities",
            tags=["gpu", "hardware", "reverse_engineering"]
        )

        # Add some objectives
        obj1 = ResearchObjective(
            id=str(uuid.uuid4()),
            title="Identify GPU command structure",
            description="Determine how commands are submitted to the GPU",
            priority=Priority.HIGH
        )

        obj2 = ResearchObjective(
            id=str(uuid.uuid4()),
            title="Map memory-mapped registers",
            description="Identify and characterize all memory-mapped I/O registers",
            priority=Priority.HIGH
        )

        orchestrator.add_objective_to_mission(mission_id, obj1)
        orchestrator.add_objective_to_mission(mission_id, obj2)

        # Start the mission
        await orchestrator.start_mission(mission_id)

        # Show system status
        status = orchestrator.get_system_status()
        print(json.dumps(status, indent=2))

        # Stop the orchestrator
        await orchestrator.stop()

    # Run the example
    asyncio.run(main())