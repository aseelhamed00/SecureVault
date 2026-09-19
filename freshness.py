def check_freshness(
    state,
    sender_id,
    document_id,
    sequence_number,
    timestamp
):
    key = (sender_id, document_id)

    if key not in state:
        state[key] = {
            "sequence_number": sequence_number,
            "timestamp": timestamp
        }
        return True

    old_sequence = state[key]["sequence_number"]
    old_timestamp = state[key]["timestamp"]

    # Reject an old or repeated sequence number
    if sequence_number <= old_sequence:
        return False

    # Reject a timestamp that goes backwards
    if timestamp < old_timestamp:
        return False

    state[key]["sequence_number"] = sequence_number
    state[key]["timestamp"] = timestamp

    return True


def save_freshness_state(filename, state):
    with open(filename, "w") as file:
        for key in state:
            sender_id, document_id = key

            sequence_number = state[key]["sequence_number"]
            timestamp = state[key]["timestamp"]

            sender_hex = sender_id.hex()
            document_hex = document_id.hex()

            file.write(
                sender_hex
                + " "
                + document_hex
                + " "
                + str(sequence_number)
                + " "
                + str(timestamp)
                + "\n"
            )


def load_freshness_state(filename):
    state = {}

    try:
        with open(filename, "r") as file:
            for line in file:
                parts = line.strip().split()

                if len(parts) != 4:
                    continue

                sender_id = bytes.fromhex(parts[0])
                document_id = bytes.fromhex(parts[1])
                sequence_number = int(parts[2])
                timestamp = int(parts[3])

                state[(sender_id, document_id)] = {
                    "sequence_number": sequence_number,
                    "timestamp": timestamp
                }

    except FileNotFoundError:
        pass

    return state


def remove_freshness_state(state, sender_id, document_id):
    key = (sender_id, document_id)

    if key in state:
        del state[key]
        return True

    return False