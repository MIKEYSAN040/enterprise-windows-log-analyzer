"""
parser.py
---------
Reads a raw Windows .evtx log file and converts every event record into a
simple, flat Python dictionary that the rest of the tool can work with.


"""

from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from datetime import datetime

# The XML namespace Windows puts on every event - required to query tags with ElementTree
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_time(raw_time: str):
    """Windows timestamps look like '2020-09-09 13:18:23.627951+00:00'."""
    try:
        return datetime.fromisoformat(raw_time)
    except ValueError:
        return None


def parse_evtx(file_path: str):
    """
    Parse a single .evtx file and return a list of normalized event dicts.
    Any record that fails to parse is silently skipped (corrupted/partial
    records are common at the end of real evtx files) so one bad record
    doesn't crash the whole run.
    """
    events = []

    with Evtx(file_path) as evtx_file:
        for record in evtx_file.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue

            system = root.find("e:System", NS)
            if system is None:
                continue

            event_id_el = system.find("e:EventID", NS)
            time_el = system.find("e:TimeCreated", NS)
            computer_el = system.find("e:Computer", NS)

            event = {
                "event_id": int(event_id_el.text) if event_id_el is not None else None,
                "time": _parse_time(time_el.get("SystemTime")) if time_el is not None else None,
                "computer": computer_el.text if computer_el is not None else None,
                "source_file": file_path,
            }

            # Every <Data Name="X">value</Data> under EventData becomes event["X"] = "value"
            event_data = root.find("e:EventData", NS)
            if event_data is not None:
                for data in event_data.findall("e:Data", NS):
                    name = data.get("Name")
                    if name:
                        event[name] = data.text

            events.append(event)

    return events


def parse_multiple(file_paths):
    """Parse several .evtx files and merge them into one sorted timeline."""
    all_events = []
    for path in file_paths:
        all_events.extend(parse_evtx(path))

    all_events.sort(key=lambda e: e["time"] or datetime.min)
    return all_events
