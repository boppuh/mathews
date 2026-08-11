"""Shared readiness and handoff constants without workflow import cycles."""

HANDOFF_MEANING = (
    "Automation responsibility has ended; this does not mean merged, deployed, "
    "delivered, or released."
)
HANDOFF_ACKNOWLEDGEMENT = (
    "I acknowledge that automation is complete and that merge, deployment, "
    "delivery, and release remain human responsibilities."
)


class ReadinessError(RuntimeError):
    """Stable readiness refusal without evidence or review contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)
