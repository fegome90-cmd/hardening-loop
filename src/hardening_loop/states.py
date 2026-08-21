"""State machine and lifecycle governance for WorkUnit and Knowledge."""

from .models import HardeningState, WorkUnit, utc_now_iso


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal transition is attempted on a WorkUnit."""

    pass


VALID_TRANSITIONS: dict[HardeningState, set[HardeningState]] = {
    HardeningState.DRAFT: {HardeningState.AUDITING},
    HardeningState.AUDITING: {HardeningState.PATCH_PROPOSED, HardeningState.DRAFT},
    HardeningState.PATCH_PROPOSED: {HardeningState.VERIFIED, HardeningState.AUDITING},
    HardeningState.VERIFIED: {HardeningState.KNOWLEDGE_CANDIDATE, HardeningState.AUDITING},
    HardeningState.KNOWLEDGE_CANDIDATE: {HardeningState.ADMITTED, HardeningState.DEPRECATED},
    HardeningState.ADMITTED: {HardeningState.READY_FOR_PR_REVIEW, HardeningState.CANONICAL, HardeningState.DEPRECATED},
    HardeningState.READY_FOR_PR_REVIEW: {HardeningState.CANONICAL, HardeningState.DEPRECATED},
    HardeningState.CANONICAL: {HardeningState.DEPRECATED},
    HardeningState.DEPRECATED: set(),
}


class StateMachine:
    """Governs atomic state progression for WorkUnits."""

    @staticmethod
    def can_transition(current: HardeningState, target: HardeningState) -> bool:
        return target in VALID_TRANSITIONS.get(current, set())

    @staticmethod
    def transition(work_unit: WorkUnit, target: HardeningState, reason: str = "") -> WorkUnit:
        if not StateMachine.can_transition(work_unit.state, target):
            raise InvalidStateTransitionError(
                f"Cannot transition WorkUnit '{work_unit.work_unit_id}' from {work_unit.state.value} to {target.value}. "
                f"Valid targets: {[s.value for s in VALID_TRANSITIONS.get(work_unit.state, set())]}"
            )
        work_unit.state = target
        work_unit.updated_at = utc_now_iso()
        if reason:
            work_unit.metadata.setdefault("transition_history", []).append(
                {
                    "from": work_unit.state.value,
                    "to": target.value,
                    "reason": reason,
                    "timestamp": work_unit.updated_at,
                }
            )
        return work_unit
