#!/usr/bin/env python3
"""
Startup script for the Reverse Engineering Lab
Demonstrates how to initialize and use the system
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

# Import our modules
from orchestrator import orchestrator, create_research_mission
from agents.base_agent import AgentPriority
from agents.binary_analysis_agent import create_binary_analysis_agent
from knowledge_base import add_fact, add_hypothesis, add_experiment
import config.settings as settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(project_root / "logs" / "startup.log")
    ]
)

logger = logging.getLogger("startup")


async def initialize_system():
    """Initialize the reverse engineering lab system"""
    logger.info("Initializing Reverse Engineering Lab...")

    # Start the orchestrator
    await orchestrator.start()
    logger.info("Orchestrator started")

    # Register agent types
    orchestrator.register_agent_type("binary_analysis",
                                  lambda agent_id=None: create_binary_analysis_agent(agent_id))
    logger.info("Registered binary analysis agent type")

    # In a real implementation, we would register other agent types here
    # orchestrator.register_agent_type("firmware_analysis", FirmwareAnalysisAgent)
    # orchestrator.register_agent_type("hardware_behavior", HardwareBehaviorAgent)
    # etc.

    logger.info("System initialization complete")


async def demonstrate_capabilities():
    """Demonstrate the system's capabilities with a sample investigation"""
    logger.info("=== Starting Capability Demonstration ===")

    # Create a research mission
    mission_id = create_research_mission(
        title="IoT Device Firmware Investigation",
        description="Analyze firmware from an unknown IoT device to understand its functionality and identify potential security issues",
        tags=["iot", "firmware", "security_assessment"],
        created_by="demonstration_script"
    )

    logger.info(f"Created research mission: {mission_id}")

    # Create and register some binary analysis agents
    agent1 = create_binary_analysis_agent("binary_agent_001")
    agent2 = create_binary_analysis_agent("binary_agent_002")

    # Initialize agents
    logger.info("Initializing analysis agents...")
    await agent1.initialize()
    await agent2.initialize()

    # Register agents with the orchestrator
    orchestrator.agent_manager.register_agent(agent1)
    orchestrator.agent_manager.register_agent(agent2)
    logger.info(f"Registered {len(orchestrator.agent_manager.agents)} agents")

    # Add some initial knowledge to the knowledge base
    logger.info("Adding initial knowledge to knowledge base...")

    fact_id = add_fact(
        title="Common firmware file signatures",
        description="Firmware images often start with specific signatures that indicate their format and architecture",
        confidence=0.9,
        evidence=["Reverse engineering textbooks", "Firmware analysis experience"],
        source_references=["Practical Reverse Engineering p. 45", "Embedded Systems Security"],
        tags=["firmware", "signatures", "reference"],
        source_agent="system"
    )

    hypothesis_id = add_hypothesis(
        title="Device uses ARM Cortex-M architecture",
        description="Based on the device's power characteristics and cost constraints, it likely uses an ARM Cortex-M MCU",
        confidence=0.6,
        basis="Device marketed as low-cost IoT sensor with battery operation",
        prediction="Disassembly will show ARM Thumb instruction patterns",
        falsification_condition="Discovery of x86 or MIPS instruction patterns",
        tags=["architecture", "hypothesis", "arm"],
        source_agent="system"
    )

    # Link the hypothesis to the fact
    orchestrator.knowledge_base.link_items(fact_id, hypothesis_id, "informing")
    logger.info(f"Added initial knowledge: fact ({fact_id}), hypothesis ({hypothesis_id})")

    # Assign agents to the mission
    orchestrator.assign_agent_to_mission(mission_id, agent1)
    orchestrator.assign_agent_to_mission(mission_id, agent2)
    logger.info(f"Assigned {len(orchestrator.agent_manager.agents)} agents to mission")

    # Create analysis tasks for the agents
    logger.info("Creating analysis tasks...")

    # In a real scenario, we would have actual firmware files to analyze
    # For demonstration, we'll create tasks that would analyze hypothetical files

    from agents.base_agent import Task

    # Task 1: Basic firmware analysis
    task1 = Task(
        task_id="fw_analysis_001",
        description="Perform basic analysis on IoT device firmware",
        agent_type="binary_analysis",
        priority=AgentPriority.HIGH.value,
        parameters={
            "file_path": "/firmware/iot_device_v1.2.bin",
            "analysis_type": "comprehensive"
        }
    )

    # Task 2: String analysis to find credentials or URLs
    task2 = Task(
        task_id="fw_analysis_002",
        description="Extract and analyze strings from firmware for sensitive information",
        agent_type="binary_analysis",
        priority=AgentPriority.HIGH.value,
        parameters={
            "file_path": "/firmware/iot_device_v1.2.bin",
            "analysis_type": "strings",
            "min_length": 6,
            "max_results": 50
        }
    )

    # Task 3: Import analysis to understand dependencies
    task3 = Task(
        task_id="fw_analysis_003",
        description="Analyze imported functions to understand device capabilities",
        agent_type="binary_analysis",
        priority=AgentPriority.MEDIUM.value,
        parameters={
            "file_path": "/firmware/iot_device_v1.2.bin",
            "analysis_type": "imports"
        }
    )

    # Task 4: Security analysis to find potential vulnerabilities
    task4 = Task(
        task_id="fw_analysis_004",
        description="Perform security analysis to identify potential vulnerabilities",
        agent_type="binary_analysis",
        priority=AgentPriority.HIGH.value,
        parameters={
            "file_path": "/firmware/iot_device_v1.2.bin",
            "analysis_type": "security"
        }
    )

    # Add tasks to the scheduler's queue
    from orchestrator import task_scheduler
    task_scheduler.add_task(task1)
    task_scheduler.add_task(task2)
    task_scheduler.add_task(task3)
    task_scheduler.add_task(task4)

    logger.info(f"Added {len([task1, task2, task3, task4])} analysis tasks to queue")

    # Wait for tasks to be processed (in a real system, this would happen continuously)
    logger.info("Processing tasks... (waiting 10 seconds)")
    await asyncio.sleep(10)

    # Check results
    stats = orchestrator.get_system_status()
    logger.info(f"System status after task processing: {stats['task_queue_stats']}")

    # Query knowledge base for findings
    logger.info("Querying knowledge base for results...")

    from knowledge_base import kb
    firmware_facts = kb.search_knowledge(
        query="firmware",
        limit=10
    )

    logger.info(f"Found {len(firmware_facts)} firmware-related knowledge items:")
    for fact in firmware_facts:
        logger.info(f"  - [{fact.type.value}] {fact.title} (confidence: {fact.confidence:.2f})")

    # Show mission status
    mission = orchestrator.missions.get(mission_id)
    if mission:
        logger.info(f"Mission status: {mission.status.value}")
        logger.info(f"Mission objectives: {len(mission.objectives)}")
        logger.info(f"Mission agents: {len(mission.agents)}")

    # Cleanup
    logger.info("Cleaning up agents...")
    await agent1.cleanup()
    await agent2.cleanup()

    logger.info("=== Capability Demonstration Complete ===")


async def main():
    """Main entry point"""
    try:
        # Initialize the system
        await initialize_system()

        # Run the demonstration
        await demonstrate_capabilities()

        # Show final system status
        final_status = orchestrator.get_system_status()
        logger.info("=== Final System Status ===")
        logger.info(f"Total agents: {final_status['total_agents']}")
        logger.info(f"Available agents: {final_status['available_agents']}")
        logger.info(f"Knowledge base items: {final_status['knowledge_base_stats']['total_items']}")
        logger.info(f"Average confidence: {final_status['knowledge_base_stats']['average_confidence']}")

        # Keep system running for a bit to allow inspection
        logger.info("System will remain running for 30 seconds for inspection...")
        await asyncio.sleep(30)

    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logger.error(f"Error in main execution: {e}", exc_info=True)
    finally:
        # Shutdown gracefully
        logger.info("Shutting down system...")
        await orchestrator.stop()
        logger.info("System shutdown complete")


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())