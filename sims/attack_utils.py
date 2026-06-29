import random

from config import ATTACK_RETRANSMIT_PROBABILITY, PAYLOAD_SIZE, RETRANSMIT_HISTORY_SIZE


def next_attack_seq(state):
    history = state.setdefault("seq_history", [])

    if history and random.random() < ATTACK_RETRANSMIT_PROBABILITY:
        return random.choice(history)

    seq = state["seq"]
    state["seq"] += PAYLOAD_SIZE
    history.append(seq)
    if len(history) > RETRANSMIT_HISTORY_SIZE:
        del history[0]
    return seq
