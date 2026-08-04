#!/usr/bin/env python3
"""
Example usage of the Reverse Engineering Lab
Demonstrates a typical workflow for analyzing a binary file
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

from orchestrator import orchestrator, create_research_mission
from agents.binary_analysis_agent import create_binary_analysis_agent
from knowledge_base import add_fact, add_hypothesis, add_experiment, kb

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('example_analysis.log')
    ]
)

logger = logging.getLogger("example_usage")


async def run_example_analysis():
    """Run a complete example analysis workflow"""
    logger.info("=== Reverse Engineering Lab Example ===")
    logger.info("Starting analysis of a hypothetical IoT device firmware")

    # 1. Start the system
    logger.info("1. Initializing system...")
    await orchestrator.start()

    # 2. Create and register binary analysis agents
    logger.info("2. Setting up analysis agents...")
    binary_agent_1 = create_binary_analysis_agent("binary_agent_001")
    binary_agent_2 = create_binary_analysis_agent("binary_agent_002")

    # Initialize agents
    await binary_agent_1.initialize()
    await binary_agent_2.initialize()

    # Register agents
    orchestrator.agent_manager.register_agent(binary_agent_1)
    orchestrator.agent_manager.register_agent(binary_agent_2)

    logger.info(f"Registered {len(orchestrator.agent_manager.agents)} binary analysis agents")

    # 3. Create a research mission
    logger.info("3. Creating research mission...")
    mission_id = create_research_mission(
        title="IoT Smart Lock Firmware Analysis",
        description="Analyze firmware from a smart lock device to understand its functionality, "
                   "identify communication protocols, and assess security posture",
        tags=["iot", "firmware", "security", "smart_lock"],
        created_by="security_researcher_alice"
    )

    logger.info(f"Created mission: {mission_id}")

    # 4. Assign agents to the mission
    logger.info("4. Assigning agents to mission...")
    orchestrator.assign_agent_to_mission(mission_id, binary_agent_1)
    orchestrator.assign_agent_to_mission(mission_id, binary_agent_2)

    # 5. Add initial knowledge based on reconnaissance
    logger.info("5. Adding initial reconnaissance knowledge...")

    # Fact from external research
    recon_fact_id = add_fact(
        title="Device uses ESP32-WROOM-32 module",
        description="Based on FCC IDs and teardown photos, the device uses an ESP32-WROOM-32 module "
                   "with dual-core Tensilica LX6 microprocessor and integrated 2.4 GHz Wi-Fi/BLE",
        confidence=0.85,
        evidence=["FCC ID: 2ABCDE-ESP32MODULE", "Teardown video timestamps"],
        source_references=["FCC Exhibit File", "YouTube Teardown by @ElectroExplore"],
        tags=["hardware", "esp32", "microcontroller", "wifi"],
        source_agent="recon_team"
    )

    # Hypothesis about communication
    comm_hypothesis_id = add_hypothesis(
        title="Device uses MQTT for cloud communication",
        description="Based on the IoT nature and Wi-Fi capability, the device likely uses MQTT "
                   "to communicate with a cloud backend for remote control and monitoring",
        confidence=0.7,
        basis="IoT device pattern: Wi-Fi + sensors/actuators typically use MQTT for lightweight messaging",
        prediction="Network traffic analysis will show TCP connections to port 1883 or 8883",
        falsification_condition="No MQTT traffic observed; instead finds HTTP/REST or CoAP",
        tags=["communication", "mqtt", "iot", "hypothesis"],
        source_agent="threat_analyst_bob"
    )

    # Link the hypothesis to the hardware fact
    kb.link_items(recon_fact_id, comm_hypothesis_id, "supports")
    logger.info(f"Added reconnaissance knowledge: fact ({recon_fact_id}), hypothesis ({comm_hypothesis_id})")

    # 6. Create analysis tasks (simulating having the actual firmware file)
    logger.info("6. Creating analysis tasks...")

    from agents.base_agent import Task

    # Note: In a real scenario, these would point to actual firmware files
    # For this example, we'll use non-existent paths to demonstrate the task creation flow

    tasks = []

    # Task 1: Firmware format and architecture identification
    task1 = Task(
        task_id="fw_analysis_format_001",
        description="Determine firmware format, architecture, and entry point",
        agent_type="binary_analysis",
        priority=2,  # HIGH
        parameters={
            "file_path": "/firmware/smartlock_v2.1.bin",
            "analysis_type": "basic"
        }
    )
    tasks.append(task1)

    # Task 2: String analysis for URLs, IP addresses, and credentials
    task2 = Task(
        task_id="fw_analysis_strings_001",
        description="Extract strings to find C2 servers, API endpoints, and potential credentials",
        agent_type="binary_analysis",
        priority=2,  # HIGH
        parameters={
            "file_path": "/firmware/smartlock_v2.1.bin",
            "analysis_type": "strings",
            "min_length": 4,
            "max_results": 100
        }
    )
    tasks.append(task2)

    # Task 3: Import analysis to understand libraries and capabilities
    task3 = Task(
        task_id="fw_analysis_imports_001",
        description="Identify imported libraries and functions to understand device capabilities",
        agent_type="binary_analysis",
        priority=3,  # MEDIUM
        parameters={
            "file_path": "/firmware/smartlock_v2.1.bin",
            "analysis_type": "imports"
        }
    )
    tasks.append(task3)

    # Task 4: Function analysis to understand control flow
    task4 = Task(
        task_id="fw_analysis_functions_001",
        description="Analyze functions to understand program structure and identify security-relevant code",
        agent_type="binary_analysis",
        priority=3,  # MEDIUM
        parameters={
            "file_path": "/firmware/smartlock_v2.1.bin",
            "analysis_type": "functions"
        }
    )
    tasks.append(task4)

    # Task 5: Security analysis for vulnerabilities
    task5 = Task(
        task_id="fw_analysis_security_001",
        description="Perform security analysis to identify potential vulnerabilities",
        agent_type="binary_analysis",
        priority=1,  # CRITICAL
        parameters={
            "file_path": "/firmware/smartlock_v2.1.bin",
            "analysis_type": "security"
        }
    )
    tasks.append(task5)

    logger.info(f"Created {len(tasks)} analysis tasks")

    # 7. Submit tasks to the orchestrator's task queue
    logger.info("7. Submitting tasks to processing queue...")
    for task in tasks:
        orchestrator.task_scheduler.add_task(task)
        logger.debug(f"Queued task: {task.task_id} - {task.description}")

    # 8. Process the tasks (this would run in the background)
    logger.info("8. Starting task processing...")

    # Give some time for tasks to be processed
    # In a real deployment, this would run continuously
    processing_task = asyncio.create_task(
        orchestrator.task_scheduler.process_task_queue(max_concurrent=2)
    )

    # Wait a bit for processing to start processing
    await asyncio.sleep(3)

    # Check progress
    stats = orchestrator.get_system_status()
    logger.info(f"Current system status:")
    logger.info(f"  - Tasks queued: {stats['task_queue_stats']['total_queued']}")
    logger.info(f"  - Tasks completed: {stats['task_queue_stats']['completed']}")
    logger.info(f"  - Tasks failed: {stats['task_queue_stats']['failed']}")
    logger.info(f"  - Available agents: {stats['available_agents']}")
    logger.info(f"  - Knowledge base items: {stats['knowledge_base_stats']['total_items']}")

    # 9. Add some example findings that would come from analysis
    logger.info("9. Adding example analysis results to knowledge base...")

    # Simulate finding an MQTT connection string in the firmware
    mqtt_finding_id = add_fact(
        title="MQTT broker configuration found in firmware",
        description="Discovered hardcoded MQTT broker address 'mqtt.company.com:1883' and client ID 'device_*' in strings",
        confidence=0.9,
        evidence=["String analysis of firmware", "Cross-reference with network handler functions"],
        source_references=["/firmware/smartlock_v2.1.bin"],
        tags=["mqtt", "configuration", "hardcoded_credentials", "network"],
        source_agent="binary_agent_001"
    )

    # Link this finding to our earlier hypothesis
    kb.link_items(mqtt_finding_id, comm_hypothesis_id, "confirms")
    logger.info(f"Added MQTT finding: {mqtt_finding_id}")

    # Simulate finding a potential buffer overflow
    vuln_finding_id = add_fact(
        title="Potential buffer overflow in UART command handler",
        description="Found function 'handle_uart_command' that uses strcpy without bounds checking on user input",
        confidence=0.75,
        evidence=["Function decompilation shows strcpy(dest, user_input) with no length checking"],
        source_references=["/firmware/smartlock_v2.1.bin@0x400A50"],
        tags=["vulnerability", "buffer_overflow", "uart", "cwe-120"],
        source_agent="binary_agent_002"
    )

    # Create a hypothesis about exploitability
    exploit_hypothesis_id = add_hypothesis(
        title="UART buffer overflow is exploitable for code execution",
        description="Given the lack of stack protection and ASMI in this embedded device, "
                   "the buffer overflow could allow arbitrary code execution",
        confidence=0.6,
        basis="Embedded devices often lack modern exploit mitigations like ASLR, DEP, stack canaries",
        prediction="Overflow would allow overwriting return address and executing shellcode",
        falsification_condition("Device shows crash/restart behavior without code execution when overflow triggered"),
        tags=["exploit", "buffer_overflow", "arm", "embedded"],
        source_agent="vulnerability_researcher_carl"
    )

    # Link vulnerability to exploit hypothesis
    kb.link_items(vuln_finding_id, exploit_hypothesis_id, "enables")
    logger.info(f"Added vulnerability finding: {vuln_finding_id}")
    logger.info(f"Added exploit hypothesis: {exploit_hypothesis_id}")

    # Create an experiment to test the vulnerability
    exp_id = add_experiment(
        title="Test UART buffer overflow exploitability",
        description="Connect to UART interface and attempt to overflow the command buffer with increasing payload sizes",
        confidence=0.8,
        hypothesis_id=exploit_hypothesis_id,
        setup="Device connected to logic analyzer on UART TX/RX lines, power supply monitored",
        procedure="1. Send normal commands to establish baseline\n"
                 "2. Send increasingly long input strings to UART command handler\n"
                 "3. Monitor for system crashes, resets, or unusual behavior\n"
                 "4. Try to inject known address patterns to test control flow hijacking",
        results="",  # Would be filled after experiment
        conclusion="",  # Would be filled after experiment
        replicated=False,
        replication_count=0,
        tags=["experiment", "buffer_overflow", "uart", "exploit_test"],
        source_agent="experiment_design_alice"
    )

    # Link experiment to hypothesis and vulnerability
    kb.link_items(exploit_hypothesis_id, exp_id, "tests")
    kb.link_items(vuln_finding_id, exp_id, "tests")
    logger.info(f"Created experiment: {exp_id}")

    # 10. Check final knowledge base state
    logger.info("10. Final knowledge base status...")
    kb_stats = kb.get_statistics()
    logger.info(f"Knowledge base statistics:")
    logger.info(f"  - Total items: {kb_stats['total_items']}")
    for ktype, count in kb_stats['type_breakdown'].items():
        logger.info(f"  - {ktype}: {count}")
    logger.info(f"  - Average confidence: {kb_stats['average_confidence']}")
    logger.info(f"  - Added in last 24h: {kb_stats['recent_24h']}")

    # 11. Show some example queries
    logger.info("11. Example knowledge queries...")

    # Find all high-confidence facts
    high_conf_facts = kb.search_knowledge(
        ktype=None,
        min_confidence=0.8,
        limit=10
    )
    logger.info(f"Found {len(high_conf_facts)} high-confidence items (≥0.8)")

    # Find all vulnerability-related items
    vuln_items = kb.search_knowledge(
        query="vulnerability",
        limit=10
    )
    logger.info(f"Found {len(vuln_items)} vulnerability-related items")

    # Find all MQTT-related items
    mqtt_items = kb.search_knowledge(
        query="mqtt",
        limit=10
    )
    logger.info(f"Found {len(mqtt_items)} MQTT-related items")

    # 12. Clean up
    logger.info("12. Cleaning up...")

    # Stop processing (in real usage, this would continue)
    processing_task.cancel()
    try:
        await processing_task
    except asyncio.CancelledError:
        pass

    # Shutdown agents
    await binary_agent_1.cleanup()
    await binary_agent_2.cleanup()

    # Stop orchestrator
    await orchestrator.stop()

    logger.info("=== Example Analysis Complete ===")
    logger.info("Summary of what was accomplished:")
    logger.info("  ✓ System initialized with orchestrator and agents")
    logger.info("  ✓ Research mission created and agents assigned")
    logger.info("  ✓ Initial reconnaissance knowledge added")
    logger.info("  ✓ Analysis tasks created and queued")
    logger.info("  ✓ Example findings added to knowledge base")
    logger.info("  ✓ Relationships established between facts, hypotheses, and experiments")
    logger.info("  ✓ Knowledge base queried for insights")
    logger.info("")
    logger.info("Next steps in a real analysis would include:")
    logger.info("  1. Waiting for task processing to complete with actual firmware")
    logger.info("  2. Reviewing analysis results from agents")
    logger.info("  ✓ Formulating and testing additional hypotheses")
    logger.info("  3. Designing and executing experiments to validate findings")
    logger.info("  4. Iteratively building understanding through evidence")
    logger.info("  5. Producing actionable security recommendations")

    return True


def main():
    """Main entry point"""
    try:
        success = asyncio.run(run_example_analysis())
        if success:
            print("\n✅ Example completed successfully!")
            print("Check 'example_analysis.log' for detailed logs.")
            return 0
        else:
            print("\n❌ Example failed!")
            return 1
    except Exception as e:
        logger.error(f"Example failed with exception: {e}", exc_info=True)
        print(f"\n💥 Example failed with exception: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())