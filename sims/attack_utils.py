import os
import random

from config import ATTACK_RETRANSMIT_PROBABILITY, PAYLOAD_SIZE, RETRANSMIT_HISTORY_SIZE


def next_attack_seq(state):
    model = os.environ.get("ATTACK_MODEL", "netem")

    if model == "backlog":
        # Backlog spoof model (random choice from history)
        history = state.setdefault("seq_history", [])
        if history and random.random() < ATTACK_RETRANSMIT_PROBABILITY:
            return random.choice(history)

        seq = state["seq"]
        state["seq"] += PAYLOAD_SIZE
        history.append(seq)
        if len(history) > RETRANSMIT_HISTORY_SIZE:
            del history[0]
        return seq
    else:
        # Netem spoof model (back-to-back duplicates)
        if "last_seq" in state and random.random() < ATTACK_RETRANSMIT_PROBABILITY:
            return state["last_seq"]

        seq = state["seq"]
        state["seq"] += PAYLOAD_SIZE
        state["last_seq"] = seq
        return seq
