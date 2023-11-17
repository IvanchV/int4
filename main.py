import json

from export import generate_feed
from importing import get_malware_bazaar

if __name__ == "__main__":
    data = get_malware_bazaar()
    if data:
        feed = generate_feed(data)
    for item in feed:
        print(json.dumps(item))
