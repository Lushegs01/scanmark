"""
Print where things happen inside each recording, from capture-log.json.

Offsets are measured from the recording's own first frame, so they are the
in-points an editor scrubs to. Events from the other device are listed too
(prefixed "phone:"), because the two recordings ran at the same time and
those are the sync points.

    python timeline.py ../capture-log.json            # markdown tables
"""
import json
import sys
from datetime import datetime

PHONE_STILLS = ('03-', '04-', '07-')
LABELS = {
    'screenshot': lambda e: (f"phone: still `{e['name']}`" if e['name'].startswith(PHONE_STILLS)
                             else f"still `{e['name']}`"),
    'classmate.checked_in': lambda e: f"{e['name']} checks in (API); on the projector within ~1 s",
    'student.dashboard_before': lambda e: 'phone: student portal, before check-in',
    'camera.feed_written': lambda e: 'phone: camera feed taken from the projector',
    'student.scan_response': lambda e: f"phone: server answers the camera scan, {e['outcome']}",
}


def when(entry):
    return datetime.fromisoformat(entry['t'].replace('Z', '+00:00'))


def main(path):
    log = json.loads(open(path).read())
    events = log['events']
    for start in (e for e in events if e['event'] == 'recording.start'):
        stop = next(e for e in events if e['event'] == 'recording.stop' and e['name'] == start['name'])
        print(f"\n#### `{start['name']}.webm`\n\n| at | event |\n|---|---|")
        for event in events:
            if when(start) <= when(event) <= when(stop) and event['event'] in LABELS:
                offset = (when(event) - when(start)).total_seconds()
                print(f"| {int(offset // 60):02d}:{offset % 60:04.1f} | {LABELS[event['event']](event)} |")
        total = (when(stop) - when(start)).total_seconds()
        print(f"| {int(total // 60):02d}:{total % 60:04.1f} | end |")


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'capture-log.json')
