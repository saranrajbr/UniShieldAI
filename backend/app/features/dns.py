import math


def dns_entropy(qname: str) -> float:
    qname = qname.strip(".").lower()
    if not qname:
        return 0.0
    label_lengths = [len(label) for label in qname.split(".")]
    if not label_lengths:
        return 0.0
    total = float(sum(label_lengths))
    return -sum((length / total) * math.log(length / total) for length in label_lengths if length > 0)


def char_entropy(sequence: str) -> float:
    if not sequence:
        return 0.0
    length = float(len(sequence))
    counts: dict[str, int] = {}
    for ch in sequence:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log(c / length) for c in counts.values())


def dns_label_ratio(qname: str, max_labels: int = 3) -> float:
    labels = [label for label in qname.split(".") if label]
    if not labels:
        return 0.0
    return len(labels) / max_maxlabels(max_labels)


def suspicious_dns_name(qname: str, threshold: float = 3.5) -> bool:
    return char_entropy(qname.split(".")[0]) > threshold


def max_maxlabels(limit: int) -> int:
    return max(1, limit)