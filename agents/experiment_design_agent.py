"""
Experiment Design Agent Implementation
Specialized agent for designing, planning, and validating reverse engineering experiments using the scientific method
"""

import asyncio
import logging
import uuid
from typing import Dict, Any, List, Optional
from pathlib import Path

from agents.base_agent import AnalysisAgent, AgentStatus, Task, AgentResult
from knowledge_base import add_fact, add_hypothesis, add_experiment, kb

class ExperimentDesignAgent(AnalysisAgent):
    """Agent specialized in designing and managing reverse engineering experiments"""

    def __init__(self, agent_id: str = None, name: str = "Experiment Design Agent"):
        super().__init__(
            agent_id=agent_id or f"exp_design_agent_{id(self)}",
            name=name,
            description="Designs, plans, and validates reverse engineering experiments using scientific method principles"
        )
        self.agent_type = "experiment_design"
        self.supported_formats = {
            "experiment_plan", "research_protocol", "hypothesis", "data_collection_plan", "analysis_plan"
        }
        self.analysis_tools = {
            "statistical_analyzer": None,
            "experiment_tracker": None,
            "reproducibility_checker": None,
            "bias_detector": None,
            "control_group_designer": None,
            "variable_isolator": None
        }

    async def initialize(self) -> bool:
        """Initialize the experiment design agent"""
        try:
            self.logger.info("Initializing Experiment Design Agent")
            # Check for available tools (in a real implementation, this would check for actual installations)
            await self._check_available_tools()
            self.logger.info("ExperimentDesignAgent initialized successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize Experiment Design Agent: {e}")
            return False

    async def _check_available_tools(self):
        """Check which analysis tools are available"""
        # In a real implementation, this would check for actual tool installations
        # For now, we'll simulate availability
        self.analysis_tools = {
            "statistical_analyzer": True,      # Assume statistical analysis tools available
            "experiment_tracker": True,        # Assume experiment tracking available
            "reproducibility_checker": True,   # Assume reproducibility checking available
            "bias_detector": True,             # Assume bias detection available
            "control_group_designer": True,    # Assume control group design available
            "variable_isolator": True          # Assume variable isolation available
        }

        available_count = sum(1 for available in self.analysis_tools.values() if available)
        self.logger.info(f"Available experiment design tools: {available_count}/{len(self.analysis_tools)}")

    async def execute_task(self, task: Task) -> AgentResult:
        """Execute an experiment design task"""
        self.logger.info(f"Executing experiment design task: {task.description}")
        self.status = AgentStatus.PROCESSING

        try:
            # Extract task parameters
            params = task.parameters or {}
            research_question = params.get("research_question")
            hypothesis_id = params.get("hypothesis_id")
            experiment_type = params.get("experiment_type", "controlled")
            design_complexity = params.get("design_complexity", "moderate")

            if not research_question and not hypothesis_id:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    status="failed",
                    error="Either research_question or hypothesis_id must be provided",
                    result={}
                )

            # Perform experiment design based on type
            if experiment_type == "observational":
                result = await self._design_observational_study(research_question, hypothesis_id, params)
            elif experiment_type == "controlled":
                result = await self._design_controlled_experiment(research_question, hypothesis_id, params)
            elif experiment_type == "comparative":
                result = await self._design_comparative_study(research_question, hypothesis_id, params)
            elif experiment_type == "exploratory":
                result = await self._design_exploratory_study(research_question, hypothesis_id, params)
            elif experiment_type == "validation":
                result = await self._design_validation_experiment(research_question, hypothesis_id, params)
            else:
                return AgentResult(
                    task_id=task.task_id,
                    agent_id=self.agent_id,
                    status="failed",
                    error=f"Unknown experiment type: {experiment_type}",
                    result={}
                )

            # Store the experiment design in knowledge base
            experiment_id = await self._store_experiment_design(research_question, hypothesis_id, result, params)

            self.status = AgentStatus.IDLE
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                result={
                    "experiment_id": experiment_id,
                    "design": result,
                    "research_question": research_question,
                    "hypothesis_id": hypothesis_id
                }
            )

        except Exception as e:
            self.logger.error(f"Error executing experiment design task: {e}", exc_info=True)
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
        self.logger.info("Experiment Design Agent cleaned up")
        return True

    async def _design_observational_study(self, research_question: str, hypothesis_id: Optional[str], params: Dict[str, Any]) -> Dict[str, Any]:
        """Design an observational study"""
        self.logger.info(f"Designing observational study for: {research_question}")

        # In a real implementation, this would create a detailed observational study design
        # For now, we'll simulate
        design = {
            "study_type": "observational",
            "research_question": research_question,
            "hypothesis_id": hypothesis_id,
            "design_id": str(uuid.uuid4()),
            "variables": {
                "independent": [],
                "dependent": [],
                "control": [],
                "confounding": []
            },
            "data_collection": {
                "methods": ["passive_monitoring", "log_analysis", "traffic_capture"],
                "instruments": ["network_sniffer", "system_logger", "debugger"],
                "frequency": "continuous",
                "duration": "7_days"
            },
            "sampling": {
                "method": "convenience",
                "population": "all_available_samples",
                "sample_size": "n=all_observed_events",
                "bias_mitigation": ["time_of_day_variation", "different_environments"]
            },
            "ethical_considerations": {
                "privacy": "anonymize_personal_data",
                "consent": "not_required_for_passive_observation",
                "data_retention": "30_days"
            },
            "analysis_plan": {
                "statistical_methods": ["descriptive_statistics", "correlation_analysis", "time_series_analysis"],
                "software_tools": ["R", "Python_pandas", "Wireshark"],
                "validation": ["inter_coder_reliability", "triangulation"]
            },
            "expected_outcomes": {
                "primary": "descriptive_patterns_and_correlations",
                "secondary": "hypothesis_generation_for_future_testing"
            },
            "limitations": [
                "cannot_establish_causality",
                "potential_observer_bias",
                "limited_control_over_variables"
            ],
            "timestamp": "2024-01-15T10:30:00Z"
        }

        return design

    async def _design_controlled_experiment(self, research_question: str, hypothesis_id: Optional[str], params: Dict[str, Any]) -> Dict[str, Any]:
        """Design a controlled experiment"""
        self.logger.info(f"Designing controlled experiment for: {research_question}")

        # In a real implementation, this would create a detailed controlled experiment design
        # For now, we'll simulate
        design = {
            "study_type": "controlled_experiment",
            "research_question": research_question,
            "hypothesis_id": hypothesis_id,
            "design_id": str(uuid.uuid4()),
            "variables": {
                "independent": [
                    {"name": "compiler_optimization_level", "levels": ["O0", "O1", "O2", "O3", "Os", "Oz"], "type": "categorical"},
                    {"name": "input_size", "levels": ["small", "medium", "large"], "type": "ordinal"}
                ],
                "dependent": [
                    {"name": "execution_time", "units": "milliseconds", "type": "ratio"},
                    {"name": "memory_usage", "units": "kilobytes", "type": "ratio"},
                    {"name": "binary_size", "units": "bytes", "type": "ratio"}
                ],
                "control": [
                    {"name": "hardware_platform", "value": "x86_64_Linux_5.10", "type": "constant"},
                    {"name": "operating_system", "value": "Ubuntu_20.04_LTS", "type": "constant"},
                    {"name": "compiler", "value": "gcc_10.2.0", "type": "constant"}
                ],
                "confounding": [
                    {"name": "background_processes", "mitigation": "run_in_isolated_container"},
                    {"name": "CPU_temperature", "mitigation": "allow_cooldown_between_runs"}
                ]
            },
            "experimental_design": {
                "type": "factorial",
                "factors": 2,
                "levels_per_factor": [4, 3],  # 4 opt levels, 3 input sizes
                "total_conditions": 12,
                "replicates": 5,
                "total_runs": 60,
                "randomization": "complete_randomization",
                "blocking": "none"
            },
            "procedure": {
                "setup": [
                    "1. Install compiler with specific optimization level",
                    "2. Prepare test input of specified size",
                    "3. Execute target program with input",
                    "4. Measure execution time, memory usage, and output size",
                    "5. Record all metrics",
                    "6. Clean up environment"
                ],
                "controls": [
                    "Use same binary for all runs of same condition",
                    "Disable ASLR for memory consistency",
                    "Run in isolated container to minimize background interference",
                    "Allow system to return to idle state between runs"
                ],
                "measurements": {
                    "execution_time": "high_resolution_timer(nanosecond_precision)",
                    "memory_usage": "peak_resident_set_size_via_psapi",
                    "binary_size": "file_size_of_output_binary"
                }
            },
            "data_analysis": {
                "primary_analysis": "two_way_ANOVA_with_interaction",
                "post_hoc_tests": ["Tukey_HSD"],
                "assumption_checks": ["normality_Shapiro_Wilk", "homogeneity_of_variance_Levene"],
                "effect_size": "partial_eta_squared",
                "software": "R_with_car_and_emmeans_packages",
                "significance_level": 0.05
            },
            "validity": {
                "internal": "high_via_control_and_randomization",
                "external": "limited_to_specific_compiler_and_architecture",
                "construct": "adequate_via_well_defined_operationalizations",
                "statistical": "adequate_via_proper_sample_size_and_assumption_checking"
            },
            "resources_required": {
                "time": "4_hours_setup_plus_2_hours_per_replication_block",
                "equipment": ["standard_x86_64_machine", "8GB_RAM"],
                "software": ["gcc_10.2.0", "make", "automated_testing_framework"]
            },
            "timestamp": "2024-01-15T10:30:00Z"
        }

        return design

    async def _design_comparative_study(self, research_question: str, hypothesis_id: Optional[str], params: Dict[str, Any]) -> Dict[str, Any]:
        """Design a comparative study"""
        self.logger.info(f"Designing comparative study for: {research_question}")

        # In a real implementation, this would create a detailed comparative study design
        # For now, we'll simulate
        design = {
            "study_type": "comparative_study",
            "research_question": research_question,
            "hypothesis_id": hypothesis_id,
            "design_id": str(uuid.uuid4()),
            "groups": {
                "treatment": {
                    "description": "New reverse engineering technique being evaluated",
                    "sample_size": 30,
                    "selection_criteria": "volunteers_with_reverse_engineering_experience"
                },
                "control": {
                    "description": "Standard reverse engineering methodology",
                    "sample_size": 30,
                    "selection_criteria": "volunteers_with_reverse_engineering_experience"
                }
            },
            "variables": {
                "independent": [
                    {"name": "methodology", "levels": ["new_technique", "standard_approach"], "type": "nominal"}
                ],
                "dependent": [
                    {"name": "time_to_completion", "units": "minutes", "type": "ratio"},
                    {"name": "accuracy_score", "scale": "0-100", "type": "interval"},
                    {"name": "confidence_rating", "scale": "1-5_Likert", "type": "ordinal"}
                ]
            },
            "procedure": {
                "recruitment": "targeted_outreach_to_reverse_engineering_community",
                "randomization": "simple_random_assignment_to_groups",
                "blinding": "single_blind_participants_aware_but_analysts_blinded",
                "intervention": {
                    "treatment_group": "use_new_technique_for_all_tasks",
                    "control_group": "use_standard_approach_for_all_tasks"
                },
                "data_collection": {
                    "timing": "automated_via_task_management_system",
                    "quality_assessment": "peer_review_by_expert_panel",
                    "confidence_surveys": "immediate_post_task_Likert_scale"
                }
            },
            "analysis_plan": {
                "primary_analysis": "independent_samples_t_test",
                "effect_size": "cohens_d",
                "confidence_interval": "95%",
                "normality_check": "Shapiro_Wilk_test",
                "equality_of_variance": "Levene_test",
                "non_parametric_alternative": "Mann_Whitney_U_test",
                "software": "SPSS_or_R"
            },
            "ethical_considerations": {
                "informed_consent": "obtained_via_digital_consent_form",
                "right_to_withdraw": "allowed_at_any_time_without_penalty",
                "data_anonymization": "participant_ids_replaced_with_random_numbers",
                "debriefing": "provided_after_study_completion"
            },
            "sample_size_justification": {
                "power_analysis": "80%_power_to_detect_medium_effect_size_d_0.5",
                "alpha": 0.05,
                "estimated_effect_size": 0.5,
                "required_n_per_group": 34,
                "actual_n_per_group": 30,
                "note": "slightly_underpowered_but_practical_constraints"
            },
            "timestamp": "2024-01-15T10:30:00Z"
        }

        return design

    async def _design_exploratory_study(self, research_question: str, hypothesis_id: Optional[str], params: Dict[str, Any]) -> Dict[str, Any]:
        """Design an exploratory study"""
        self.logger.info(f"Designing exploratory study for: {research_question}")

        # In a real implementation, this would create a detailed exploratory study design
        # For now, we'll simulate
        design = {
            "study_type": "exploratory_study",
            "research_question": research_question,
            "hypothesis_id": hypothesis_id,
            "design_id": str(uuid.uuid4()),
            "approach": "qualitative_and_quantitative_mixed_methods",
            "phases": [
                {
                    "phase": 1,
                    "name": "initial_exploration",
                    "methods": ["open_ended_interviews", "artifact_analysis", "process_tracing"],
                    "participants": "5-10_experts",
                    "duration": "2_weeks",
                    "goals": ["generate_initial_insights", "identify_key_variables", "develop_preliminary_theories"]
                },
                {
                    "phase": 2,
                    "name": "focused_investigation",
                    "methods": ["structured_observations", "task_analysis", "pattern_recognition"],
                    "participants": "15-20_practitioners",
                    "duration": "3_weeks",
                    "goals": ["test_preliminary_theories", "refine_measurement_instruments", "identify_unexpected_patterns"]
                },
                {
                    "phase": 3,
                    "name": "hypothesis_generation",
                    "methods": ["cross_case_analysis", "theoretical_sampling", "concept_mapping"],
                    "participants": "research_team_only",
                    "duration": "1_week",
                    "goals": ["formulate_testable_hypotheses", "design_followup_studies", "create_conceptual_model"]
                }
            ],
            "data_sources": {
                "primary": ["think_aloud_protocols", "video_recordings", "artifact_examinations"],
                "secondary": ["existing_literature", "online_forums", "tool_documentation"]
            },
            "analytical_approach": {
                "qualitative": ["thematic_analysis", "grounded_theory_coding", "narrative_analysis"],
                "quantitative": ["descriptive_statistics", "frequency_analysis", "basic_correlations"],
                "integration_strategy": "triangulation_protocol"
            },
            "quality_criteria": {
                "credibility": ["member_checking", "triangulation", "peer_debriefing"],
                "transferability": ["thick_description", "purposive_sampling"],
                "dependability": ["audit_trail", "code_replication"],
                "confirmability": ["reflexivity_journal", "negative_case_analysis"]
            },
            "deliverables": [
                "detailed_field_notes",
                "transcribed_interviews",
                "coding_scheme",
                "preliminary_theory_document",
                "refined_research_questions",
                "detailed_proposal_for_next_phase"
            ],
            "timestamp": "2024-01-15T10:30:00Z"
        }

        return design

    async def _design_validation_experiment(self, research_question: str, hypothesis_id: Optional[str], params: Dict[str, Any]) -> Dict[str, Any]:
        """Design a validation experiment"""
        self.logger.info(f"Designing validation experiment for: {research_question}")

        # In a real implementation, this would create a detailed validation experiment design
        # For now, we'll simulate
        design = {
            "study_type": "validation_experiment",
            "research_question": research_question,
            "hypothesis_id": hypothesis_id,
            "design_id": str(uuid.uuid4()),
            "validation_type": "construct_validation",
            "target_construct": "reverse_engineering_difficulty",
            "indicators": [
                {"name": "time_required", "operationalization": "total_time_to_complete_task"},
                {"name": "error_rate", "operationalization": "number_of_mistakes_made"},
                {"name": "confidence_level", "operationalization": "self_assessed_confidence_on_scale_1-5"},
                {"name": "help_seeking", "operationalization": "number_of_times_assistance_was_requested"}
            ],
            "procedure": {
                "participant_selection": {
                    "criteria": ["reverse_engineering_experience", "familiarity_with_target_architecture"],
                    "sample_size": 25,
                    "sampling_method": "purposive_sampling"
                },
                "materials": {
                    "target_objects": ["3_different_firmware_images", "2_unknown_binaries", "1_known_good_sample"],
                    "tools_available": ["standard_reverse_engineering_suite", "debugger", "disassembler"],
                    "documentation": ["minimal_header_information", "no_source_code_available"]
                },
                "task_administration": {
                    "instructions": "analyze_each_object_and_document_findings",
                    "time_limit": "90_minutes_per_object",
                    "environment": "quiet_workspace_with_minimal_distractions"
                },
                "data_collection": {
                    "automated": ["timestamps", "action_logs", "artifact_creation"],
                    "self_report": ["post_task_questionnaire", "difficulty_rating"],
                    "observational": ["researcher_notes", "video_recording_if_consent_given"]
                }
            },
            "analysis_plan": {
                "reliability": {
                    "internal_consistency": "Cronbachs_alpha_for_multi_item_scales",
                    "inter_rater": "Cohen_kappa_for_coded_observations",
                    "test_retest": "intraclass_correlation_if_applicable"
                },
                "validity": {
                    "content": "expert_review_of_measurement_instrument",
                    "criterion": "correlation_with_established_measures_if_available",
                    "construct": "factor_analysis_if_sufficient_items"
                },
                "descriptive_statistics": ["means", "standard_deviations", "frequency_distributions"],
                "inferential_statistics": ["correlation_analysis", "regression_if_appropriate"],
                "software": "R_or_SPSS"
            },
            "success_criteria": {
                "reliability_threshold": "Cronbachs_alpha > 0.70",
                "validity_threshold": "significant_correlations_with_expected_predicates",
                "practical_significance": "effect_sizes_above_small_threshold"
            },
            "limitations": [
                "small_sample_size_limits_generalizability",
                "potential_self_selection_bias",
                "artificial_task_context_may_not_reflect_real_world"
            ],
            "timestamp": "2024-01-15T10:30:00Z"
        }

        return design

    async def _store_experiment_design(self, research_question: str, hypothesis_id: Optional[str], design: Dict[str, Any], params: Dict[str, Any]) -> str:
        """Store the experiment design in the knowledge base as an experiment record"""
        try:
            # Create a descriptive title
            if research_question:
                title = f"Experiment design for: {research_question[:100]}..." if len(research_question) > 100 else f"Experiment design for: {research_question}"
            else:
                # Get hypothesis details if available
                hypothesis = None
                if hypothesis_id:
                    # In a real implementation, we'd fetch the hypothesis from KB
                    # For now, we'll create a placeholder
                    hypothesis = {"description": f"Hypothesis {hypothesis_id}"}
                title = f"Experiment design for hypothesis: {hypothesis.get('description', 'Unknown') if hypothesis else 'Unknown'}"

            # Create description
            description = f"Designed {design.get('study_type', 'experiment')} to investigate: {research_question or f'hypothesis {hypothesis_id}'}"
            description += f"\n\nDesign type: {design.get('study_type', 'unknown')}"
            description += f"\nVariables: {len(design.get('variables', {}).get('independent', []))} independent, {len(design.get('variables', {}).get('dependent', []))} dependent"
            description += f"\nProcedure: {design.get('procedure', {}).get('intervention', 'standard_procedure') if isinstance(design.get('procedure'), dict) else 'see-details'}"

            # Add to knowledge base as an experiment
            experiment_id = add_experiment(
                title=title,
                description=description,
                hypothesis_id=hypothesis_id,
                setup=str(design.get('procedure', {})),
                procedure=str(design.get('procedure', {})),
                results="",  # To be filled after execution
                conclusion="",  # To be filled after execution
                replicated=False,
                replication_count=0,
                tags=["experiment_design", design.get('study_type', 'unknown'), "designed_by_agent"],
                source_agent=self.agent_id
            )

            # Also store the design details as a fact for easy retrieval
            fact_title = f"Experiment design details: {design.get('study_type', 'experiment')}"
            fact_description = f"Detailed design for experiment {experiment_id}: {design.get('study_type', 'experiment')} study\n\nKey components:\n- Research question: {research_question or 'Not specified'}\n- Hypothesis ID: {hypothesis_id or 'Not specified'}\n- Design ID: {design.get('design_id', 'Not generated')}\n- Variables: {len(design.get('variables', {}).get('independent', []))} independent, {len(design.get('variables', {}).get('dependent', []))} dependent\n- Procedure steps: {len(design.get('procedure', {}).get('setup', [])) if isinstance(design.get('procedure'), dict) and 'setup' in design.get('procedure', {}) else 'Multiple'}"

            fact_id = add_fact(
                title=fact_title,
                description=fact_description,
                confidence=0.9,  # High confidence as this is a designed plan
                evidence=[f"Experiment design generated by {self.agent_id}"],
                source_references=[],  # No specific source, it's generated
                tags=["experiment_design", "design_details", "methodology"],
                source_agent=self.agent_id
            )

            self.logger.info(f"Stored experiment design in knowledge base (experiment ID: {experiment_id}, fact ID: {fact_id})")
            return experiment_id

        except Exception as e:
            self.logger.error(f"Failed to store experiment design: {e}")
            # Return a placeholder ID if storage fails
            return f"failed_to_store_{uuid.uuid4()}"

    def get_capabilities(self) -> Dict[str, Any]:
        """Get the capabilities of this agent"""
        return {
            "agent_type": self.agent_type,
            "supported_studies": ["observational", "controlled", "comparative", "exploratory", "validation"],
            "supported_formats": list(self.supported_formats),
            "available_tools": {k: v for k, v in self.analysis_tools.items() if v},
            "mcp_connected": False  # We're not using MCP in this implementation for simplicity
        }


# Factory function for easy creation
def create_experiment_design_agent(agent_id: str = None) -> ExperimentDesignAgent:
    """Create an experiment design agent"""
    return ExperimentDesignAgent(agent_id=agent_id)


# Example usage and testing
if __name__ == "__main__":
    import logging
    import json
    logging.basicConfig(level=logging.INFO)

    async def test_experiment_design_agent():
        # Create the agent
        agent = create_experiment_design_agent("exp_design_agent_001")
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
            description="Design experiment to test compiler optimization effects",
            agent_type="experiment_design",
            priority=2,  # HIGH
            parameters={
                "research_question": "How do different compiler optimization levels affect the reverse engineering difficulty of binary files?",
                "hypothesis_id": None,  # We'll use research question instead
                "experiment_type": "controlled",
                "design_complexity": "moderate"
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
    asyncio.run(test_experiment_design_agent())