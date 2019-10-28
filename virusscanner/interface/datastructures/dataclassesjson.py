import dataclasses
import json


class DataClassesJSONEncoder(json.JSONEncoder):
    def default(self, found_object):
        if dataclasses.is_dataclass(found_object):
            return dataclasses.asdict(found_object)
        if isinstance(found_object, set):
            return list(found_object)
        return super().default(found_object)
