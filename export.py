from analyze import analyze_threat_level
from importing import get_apt_etda, get_virus_total_class, get_virus_total_family, get_virus_total


def generate_feed(samples):
    feed = []
    for sample in samples:
        md5 = sample.get('md5_hash')
        sha256 = sample.get('sha256_hash')
        malware_family = sample.get('signature')
        malware_classes = get_apt_etda(malware_family) if get_apt_etda(malware_family) else get_virus_total_class(md5)
        if malware_family is None:
            malware_family = get_virus_total_family(md5)
        av_detects = get_virus_total(md5) if md5 else []
        threat_level = analyze_threat_level(malware_classes)

        feed_item = {
            "md5": md5,
            "sha256": sha256,
            "malware_class": malware_classes,
            "malware_family": malware_family,
            "av_detects": av_detects,
            "threat_level": threat_level
        }
        feed.append(feed_item)
    return feed
