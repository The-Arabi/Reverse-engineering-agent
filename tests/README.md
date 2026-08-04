# Tests for Reverse Engineering Lab

This directory contains tests for the various components of the Reverse Engineering Lab system.

## Test Structure

- `integration_test.py` - Tests the integration between components
- Unit tests for individual components would go in separate files

## Running Tests

To run the integration tests:

```bash
python -m tests.integration_test
```

Or from the project root:

```bash
python tests/integration_test.py
```

## Test Coverage

The tests cover:
- Knowledge base functionality (CRUD operations, linking, searching)
- Binary analysis agent creation and basic operations
- Orchestration system (mission creation, agent management)
- Component integration