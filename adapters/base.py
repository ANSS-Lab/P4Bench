"""LLM adapter interface for the benchmark runner."""
from abc import ABC, abstractmethod


class LLMAdapter(ABC):
    """Interface for connecting any LLM to the benchmark."""

    @abstractmethod
    def generate(self, prompt: str, task_type: str, *,
                 task_dir: str = None, feedback: str = None) -> dict:
        """
        Send a prompt to the LLM and return the parsed response.

        This MUST be a pure function of its arguments: implementations must not
        rely on or mutate per-task instance state, so that the same adapter
        object can be called concurrently from multiple threads (one task per
        thread). All per-call context arrives as arguments.

        Args:
            prompt: The formatted prompt string.
            task_type: Always 'full_program' (the model writes the complete
                P4 program plus its control-plane entries).
            task_dir: Path to the benchmark task directory for this call.
                Adapters that read task-local or pre-generated files use this;
                pure-LLM adapters ignore it.
            feedback: Feedback from a previous attempt to fold into the prompt
                (retry loop). None on the first attempt.

        Returns:
            {
                'p4_code': str,           # Generated P4 program
                'entries': dict | None,   # entries.json content (per-switch table entries)
            }
        """
