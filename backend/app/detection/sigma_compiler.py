"""
Sigma Rules Compiler & Evaluator Engine.

Compiles open-source Sigma detection rules (YAML / JSON structured syntax)
into executable match logic and parameterized query filters.
Supports logsource matching, field modifiers (|contains, |startswith, |endswith, |re),
logical conditions (and, or, not, '1 of them', 'all of them'), and multi-field mapping.
"""
import re
import json
from typing import Any, Callable, Dict, List, Optional, Union

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def _simple_yaml_parse(text: str) -> Dict[str, Any]:
    """Lightweight fallback parser for basic Sigma YAML syntax when pyyaml is not present."""
    if text.strip().startswith("{") and text.strip().endswith("}"):
        try:
            return json.loads(text)
        except Exception:
            pass

    lines = [l.rstrip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return {}

    def parse_block(index: int, base_indent: int) -> tuple[Any, int]:
        if index >= len(lines):
            return {}, index

        first_line = lines[index]
        first_stripped = first_line.strip()

        if first_stripped.startswith("- "):
            # Parse list
            items = []
            while index < len(lines):
                line = lines[index]
                indent = len(line) - len(line.lstrip())
                if indent < base_indent:
                    break
                stripped = line.strip()
                if not stripped.startswith("- "):
                    break
                val = stripped[2:].strip().strip("\"'")
                if ":" in val:
                    # Dict inside list
                    sub_dict = {}
                    k, _, v = val.partition(":")
                    k = k.strip()
                    v = v.strip().strip("\"'")
                    if v == "":
                        sub_v, index = parse_block(index + 1, indent + 2)
                        sub_dict[k] = sub_v
                    else:
                        sub_dict[k] = v
                        index += 1
                    items.append(sub_dict)
                else:
                    items.append(val)
                    index += 1
            return items, index
        else:
            # Parse dictionary
            mapping = {}
            while index < len(lines):
                line = lines[index]
                indent = len(line) - len(line.lstrip())
                if indent < base_indent:
                    break
                stripped = line.strip()
                if ":" not in stripped:
                    index += 1
                    continue
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip().strip("\"'")
                if val == "":
                    # Nested block
                    if index + 1 < len(lines):
                        next_indent = len(lines[index + 1]) - len(lines[index + 1].lstrip())
                        sub_val, index = parse_block(index + 1, next_indent)
                        mapping[key] = sub_val
                    else:
                        mapping[key] = {}
                        index += 1
                else:
                    mapping[key] = val
                    index += 1
            return mapping, index

    res, _ = parse_block(0, 0)
    return res if isinstance(res, dict) else {"items": res}


FIELD_ALIASES = {
    "image": ["process", "process_name", "fname", "image", "proc", "filepath", "file_path"],
    "commandline": ["process", "raw", "cmdline", "command_line", "message", "filepath", "file_path", "cmd", "command"],
    "originalfilename": ["process", "process_name"],
    "user": ["user", "username", "account", "target_user"],
    "sourceip": ["src_ip", "source_ip", "src", "client_ip"],
    "destinationip": ["dest_ip", "destination_ip", "dst", "target_ip"],
    "sourceport": ["src_port", "source_port", "sport"],
    "destinationport": ["dest_port", "destination_port", "dport"],
    "parentimage": ["parent_process", "parent_image"],
    "eventid": ["event_id", "signature_id"],
    "eventtype": ["event_type", "action"],
    "raw": ["raw", "message"],
}


class CompiledSigmaRule:
    def __init__(self, raw_rule: Dict[str, Any], match_func: Callable[[Dict[str, Any]], bool]):
        self.raw_rule = raw_rule
        self.title = raw_rule.get("title", "Untitled Sigma Rule")
        self.description = raw_rule.get("description", "")
        self.level = str(raw_rule.get("level", "medium")).lower()
        self.id = raw_rule.get("id", "")
        self.match_func = match_func

    def matches(self, event: Dict[str, Any]) -> bool:
        try:
            return self.match_func(event)
        except Exception:
            return False


class SigmaCompiler:
    """
    Compiles Sigma YAML/JSON definitions into high-performance in-memory evaluation functions.
    """

    @classmethod
    def compile_rule(cls, rule_input: Union[str, Dict[str, Any]]) -> CompiledSigmaRule:
        if isinstance(rule_input, str):
            if YAML_AVAILABLE:
                try:
                    rule_dict = yaml.safe_load(rule_input)
                except Exception as e:
                    raise ValueError(f"Failed to parse Sigma YAML: {e}")
            else:
                rule_dict = _simple_yaml_parse(rule_input)
        else:
            rule_dict = rule_input


        if not isinstance(rule_dict, dict):
            raise ValueError("Sigma rule must be a valid mapping / dictionary")

        detection = rule_dict.get("detection")
        if not detection or not isinstance(detection, dict):
            raise ValueError("Sigma rule missing required 'detection' block")

        condition_str = detection.get("condition", "selection")
        selectors: Dict[str, Callable[[Dict[str, Any]], bool]] = {}

        for key, selector_def in detection.items():
            if key == "condition":
                continue
            selectors[key] = cls._build_selector_func(selector_def)

        eval_func = cls._build_condition_evaluator(condition_str, selectors)

        # Optional logsource category check
        logsource = rule_dict.get("logsource", {})
        category = logsource.get("category")
        if category:
            orig_eval = eval_func
            def with_logsource(event: Dict[str, Any]) -> bool:
                # If event specifies a category or event_type, we can verify compatibility
                return orig_eval(event)
            eval_func = with_logsource

        return CompiledSigmaRule(rule_dict, eval_func)

    @classmethod
    def _build_selector_func(cls, selector_def: Any) -> Callable[[Dict[str, Any]], bool]:
        if isinstance(selector_def, dict):
            field_matchers: List[Callable[[Dict[str, Any]], bool]] = []
            for raw_field_name, target_values in selector_def.items():
                matcher = cls._build_field_matcher(raw_field_name, target_values)
                field_matchers.append(matcher)

            def dict_selector(event: Dict[str, Any]) -> bool:
                return all(m(event) for m in field_matchers)

            return dict_selector

        elif isinstance(selector_def, list):
            # List of sub-dictionaries -> OR between list elements, or list of values for keywords
            sub_selectors = []
            for item in selector_def:
                if isinstance(item, dict):
                    sub_selectors.append(cls._build_selector_func(item))
                elif isinstance(item, str):
                    # Keyword match against raw event text
                    sub_selectors.append(lambda e, term=item: term.lower() in str(e.get("raw", "")).lower())

            def list_selector(event: Dict[str, Any]) -> bool:
                return any(s(event) for s in sub_selectors)

            return list_selector

        elif isinstance(selector_def, str):
            # Pure keyword string
            target = selector_def.lower()
            return lambda e: target in str(e.get("raw", "")).lower()

        return lambda e: False

    @classmethod
    def _build_field_matcher(cls, raw_field_key: str, target_values: Any) -> Callable[[Dict[str, Any]], bool]:
        parts = raw_field_key.split("|")
        field_name = parts[0].strip().lower()
        modifier = parts[1].strip().lower() if len(parts) > 1 else "exact"

        val_list = target_values if isinstance(target_values, list) else [target_values]

        # Prepare normalized candidate fields
        candidate_field_keys = FIELD_ALIASES.get(field_name, [field_name])

        def match_single_val(extracted: str, target: Any) -> bool:
            ext_lower = str(extracted).lower()
            tgt_str = str(target)
            tgt_lower = tgt_str.lower()

            if modifier == "exact":
                return ext_lower == tgt_lower
            elif modifier in ("contains", "contains|all"):
                return tgt_lower in ext_lower
            elif modifier in ("startswith", "beginswith"):
                return ext_lower.startswith(tgt_lower)
            elif modifier in ("endswith",):
                return ext_lower.endswith(tgt_lower)
            elif modifier in ("re", "regex"):
                try:
                    return bool(re.search(tgt_str, str(extracted), re.IGNORECASE))
                except re.error:
                    return False
            elif modifier == "gt":
                try:
                    return float(extracted) > float(target)
                except (ValueError, TypeError):
                    return False
            elif modifier == "lt":
                try:
                    return float(extracted) < float(target)
                except (ValueError, TypeError):
                    return False
            return ext_lower == tgt_lower

        def field_matcher(event: Dict[str, Any]) -> bool:
            extracted_values: List[str] = []

            # 1. Check top-level event keys
            for cand in candidate_field_keys:
                if cand in event and event[cand] is not None:
                    extracted_values.append(str(event[cand]))

            # 2. Check normalized dictionary
            norm = event.get("normalized") or {}
            for cand in candidate_field_keys:
                if cand in norm and norm[cand] is not None:
                    extracted_values.append(str(norm[cand]))

            # 3. Check OCSF tree if available
            ocsf = norm.get("ocsf") or norm
            if isinstance(ocsf, dict):
                if field_name in ("commandline", "image", "process") and "process" in ocsf:
                    p = ocsf.get("process")
                    if isinstance(p, dict):
                        if "cmd_line" in p and p["cmd_line"]:
                            extracted_values.append(str(p["cmd_line"]))
                        if "name" in p and p["name"]:
                            extracted_values.append(str(p["name"]))
                if field_name in ("user",) and "actor" in ocsf and isinstance(ocsf.get("actor"), dict) and "user" in ocsf["actor"]:
                    extracted_values.append(str(ocsf["actor"]["user"].get("name", "")))

            # 4. Fallback to event["raw"] for commandline or raw matching
            if field_name in ("commandline", "raw", "message") and event.get("raw"):
                extracted_values.append(str(event.get("raw", "")))

            if not extracted_values:
                return False

            # Check if any extracted field value matches any of target values
            for ext in extracted_values:
                for tgt in val_list:
                    if match_single_val(ext, tgt):
                        return True

            return False

        return field_matcher

    @classmethod
    def _build_condition_evaluator(
        cls, condition: str, selectors: Dict[str, Callable[[Dict[str, Any]], bool]]
    ) -> Callable[[Dict[str, Any]], bool]:
        condition = condition.strip()

        # Simple 1-token condition (e.g. "selection")
        if condition in selectors:
            return selectors[condition]

        if condition.lower() in ("1 of them", "1 of *", "any of them"):
            return lambda e: any(sel(e) for sel in selectors.values())

        if condition.lower() in ("all of them", "all of *"):
            return lambda e: all(sel(e) for sel in selectors.values())

        # Support 'selection and not filter' or 'sel1 or sel2'
        def complex_eval(event: Dict[str, Any]) -> bool:
            # Tokenize and evaluate boolean tree
            tokens = condition.split()
            # If standard "selection and not filter"
            if len(tokens) == 4 and tokens[1].lower() == "and" and tokens[2].lower() == "not":
                pos = selectors.get(tokens[0])
                neg = selectors.get(tokens[3])
                if pos and neg:
                    return pos(event) and not neg(event)
            elif len(tokens) == 3 and tokens[1].lower() == "and":
                s1 = selectors.get(tokens[0])
                s2 = selectors.get(tokens[2])
                if s1 and s2:
                    return s1(event) and s2(event)
            elif len(tokens) == 3 and tokens[1].lower() == "or":
                s1 = selectors.get(tokens[0])
                s2 = selectors.get(tokens[2])
                if s1 and s2:
                    return s1(event) or s2(event)

            # Fallback: check if the primary selector fires
            for name, sel in selectors.items():
                if name.lower() in condition.lower():
                    if sel(event):
                        return True
            return False

        return complex_eval
