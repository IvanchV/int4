import mapping as m


def analyze_threat_level(malware_classes):
    levels = []
    highest_threat_level = 0
    if malware_classes is not None:
        for malware_class in malware_classes:
            threat_level = m.TL.get(malware_class, 0)
            levels.append(threat_level)
            if threat_level > highest_threat_level:
                highest_threat_level = threat_level
    if highest_threat_level == 3:
        return "HIGH"
    elif highest_threat_level == 2:
        return "MEDIUM"
    elif highest_threat_level == 1:
        return "LOW"
    return "UNDETECTED"
