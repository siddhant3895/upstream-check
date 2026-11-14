"""Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for Upstream Check.

Strictly enforces both:
- Modern stateless MCP (`2026-07-28`): requires `params._meta` with
  `io.modelcontextprotocol/protocolVersion == "2026-07-28"` and
  `io.modelcontextprotocol/clientCapabilities` on every request (including `server/discover`),
  and returns `-32022` (`UnsupportedProtocolVersionError`) with `data: {"supported": [...], "requested": ...}`.
- Legacy stateful MCP (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`): requires a complete
  `initialize` handshake (`protocolVersion`, `capabilities`, and `clientInfo` with `name` and `version`),
  performs spec-compliant legacy version negotiation, and returns `-32602` for unknown tools or invalid arguments
  (distinguishing omitted `arguments` from explicit `arguments: null` via a dedicated `_MISSING` sentinel).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from upstream_check import __version__
from upstream_check.config.models import load_config
from upstream_check.core.types import redact_text
from upstream_check.core.models import reject_nonstandard_json_constant
from upstream_check.engine import load_baseline_if_configured, run_all_checks
from upstream_check.reporters.json import format_json_report

MODERN_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSIONS = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
LATEST_LEGACY_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = [
    MODERN_PROTOCOL_VERSION,
    *LEGACY_PROTOCOL_VERSIONS,
]
UNSUPPORTED_PROTOCOL_VERSION_ERROR = -32022
VERSION_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MISSING = object()

MCP_TOOLS = [
    {
        "name": "check_upstream_sources",
        "description": (
            "Run Upstream Check availability, schema, quality, and freshness checks "
            "and return a structured JSON report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Path to upstream-check.yaml",
                    "default": "upstream-check.yaml",
                },
                "source": {
                    "type": "string",
                    "description": "Optional single source name to check",
                },
            },
        },
    },
    {
        "name": "inspect_baseline",
        "description": "Inspect the recorded schema and column baseline profile for a configured source.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "config_path": {
                    "type": "string",
                    "description": "Path to upstream-check.yaml",
                    "default": "upstream-check.yaml",
                },
                "source": {
                    "type": "string",
                    "description": "Source name to inspect",
                },
            },
            "required": ["source"],
        },
    },
]
VALID_TOOL_NAMES = {t["name"] for t in MCP_TOOLS}


def _server_meta() -> Dict[str, Any]:
    """Return canonical MCP 2026-07-28 _meta server identity block."""
    return {
        "io.modelcontextprotocol/serverInfo": {
            "name": "upstream-check-mcp",
            "version": __version__,
        }
    }


def _unsupported_version_error(
    req_id: Any,
    requested: str,
    supported: List[str],
    message: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct an official MCP -32022 UnsupportedProtocolVersionError response with supported and requested."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {
            "code": UNSUPPORTED_PROTOCOL_VERSION_ERROR,
            "message": message or f"Unsupported MCP protocol version '{requested}'.",
            "data": {
                "supported": list(supported),
                "requested": requested,
            },
        },
    }


def _validate_client_info(
    client_info: Any, field_label: str, req_id: Any
) -> Optional[Dict[str, Any]]:
    """Validate an MCP Implementation object ({'name': str, 'version': str})."""
    if not isinstance(client_info, dict):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": f"Invalid params: '{field_label}' must be a JSON object.",
            },
        }
    c_name = client_info.get("name")
    c_ver = client_info.get("version")
    if (
        not isinstance(c_name, str)
        or not c_name.strip()
        or not isinstance(c_ver, str)
        or not c_ver.strip()
    ):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": (
                    f"Invalid params: '{field_label}' requires non-empty string "
                    "'name' and 'version' fields."
                ),
            },
        }
    return None


def _validate_modern_meta(
    params: Dict[str, Any], req_id: Any
) -> Optional[Dict[str, Any]]:
    """Strictly validate MCP 2026-07-28 per-request _meta fields and protocolVersion."""
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": (
                    "Invalid params: stateless MCP 2026-07-28 requests require 'params._meta' "
                    "containing 'io.modelcontextprotocol/protocolVersion' and "
                    "'io.modelcontextprotocol/clientCapabilities'."
                ),
            },
        }

    proto_ver = meta.get("io.modelcontextprotocol/protocolVersion")
    if not isinstance(proto_ver, str) or not proto_ver.strip():
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": (
                    "Invalid params: missing required "
                    "'_meta[\"io.modelcontextprotocol/protocolVersion\"]'."
                ),
            },
        }

    client_caps = meta.get("io.modelcontextprotocol/clientCapabilities")
    if not isinstance(client_caps, dict):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": (
                    "Invalid params: missing or invalid "
                    "'_meta[\"io.modelcontextprotocol/clientCapabilities\"]' (expected object)."
                ),
            },
        }

    if "io.modelcontextprotocol/clientInfo" in meta:
        info_err = _validate_client_info(
            meta["io.modelcontextprotocol/clientInfo"],
            '_meta["io.modelcontextprotocol/clientInfo"]',
            req_id,
        )
        if info_err is not None:
            return info_err

    if proto_ver != MODERN_PROTOCOL_VERSION:
        if proto_ver in LEGACY_PROTOCOL_VERSIONS:
            return _unsupported_version_error(
                req_id=req_id,
                requested=proto_ver,
                supported=[MODERN_PROTOCOL_VERSION],
                message=(
                    f"Protocol version '{proto_ver}' is a stateful legacy version and cannot "
                    "be used in stateless '_meta'; use '2026-07-28' or perform a legacy "
                    "'initialize' handshake."
                ),
            )
        return _unsupported_version_error(
            req_id=req_id,
            requested=proto_ver,
            supported=SUPPORTED_PROTOCOL_VERSIONS,
        )

    return None


def _validate_legacy_initialize_params(
    params: Dict[str, Any], req_id: Any
) -> Optional[Dict[str, Any]]:
    """Validate required legacy initialize parameters: protocolVersion, capabilities, and clientInfo."""
    unknown_keys = set(params.keys()) - {
        "protocolVersion",
        "capabilities",
        "clientInfo",
        "_meta",
    }
    if unknown_keys:
        unk_str = ", ".join(sorted(unknown_keys))
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": f"Invalid params: unknown field(s) in 'initialize': {unk_str}.",
            },
        }

    if "protocolVersion" not in params:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": "Invalid params: 'initialize' requires 'protocolVersion'.",
            },
        }
    client_version = params.get("protocolVersion")
    if (
        not isinstance(client_version, str)
        or not client_version.strip()
        or not VERSION_DATE_RE.match(client_version.strip())
    ):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": (
                    "Invalid params: 'protocolVersion' must be a non-empty YYYY-MM-DD version string."
                ),
            },
        }
    if client_version == MODERN_PROTOCOL_VERSION:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32600,
                "message": (
                    "MCP 2026-07-28 is stateless and removed 'initialize'; "
                    "use 'server/discover' and per-request 'params._meta' instead."
                ),
                "data": {
                    "supported": list(LEGACY_PROTOCOL_VERSIONS),
                    "requested": client_version,
                },
            },
        }

    if not isinstance(params.get("capabilities"), dict):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": "Invalid params: 'initialize' requires a 'capabilities' object.",
            },
        }

    if "clientInfo" not in params:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": (
                    "Invalid params: 'initialize' requires 'clientInfo' "
                    "({'name': str, 'version': str})."
                ),
            },
        }
    info_err = _validate_client_info(params["clientInfo"], "clientInfo", req_id)
    if info_err is not None:
        return info_err

    return None


def _validate_tool_call_arguments(
    tool_name: str, raw_args: Any, req_id: Any
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Validate tools/call arguments against the tool's inputSchema before execution.

    Distinguishes an omitted 'arguments' property (raw_args is _MISSING) from an explicitly
    supplied null/non-object value (e.g. arguments: null, [], "", 0, false).
    """
    if raw_args is _MISSING:
        args: Dict[str, Any] = {}
    elif not isinstance(raw_args, dict):
        return None, {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": "Invalid params: 'arguments' must be a JSON object when provided.",
            },
        }
    else:
        args = raw_args

    unknown_arg_keys = set(args.keys()) - {"config_path", "source"}
    if unknown_arg_keys:
        unk_str = ", ".join(sorted(unknown_arg_keys))
        return None, {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": f"Invalid params: unknown argument(s) for '{tool_name}': {unk_str}.",
            },
        }

    if "config_path" in args:
        cfg_val = args["config_path"]
        if not isinstance(cfg_val, str) or not cfg_val.strip():
            return None, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'config_path' must be a non-empty string.",
                },
            }

    if tool_name == "inspect_baseline":
        src_val = args.get("source")
        if not isinstance(src_val, str) or not src_val.strip():
            return None, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": (
                        "Invalid params: 'inspect_baseline' requires a non-empty string 'source' argument."
                    ),
                },
            }
    elif "source" in args:
        src_val = args["source"]
        if not isinstance(src_val, str) or not src_val.strip():
            return None, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'source' must be a non-empty string when provided.",
                },
            }

    return args, None


def handle_mcp_request(
    req: Dict[str, Any], session: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Process a single JSON-RPC 2.0 MCP request across stateless 2026-07-28 and legacy eras."""
    if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
        return {
            "jsonrpc": "2.0",
            "id": req.get("id") if isinstance(req, dict) else None,
            "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 request"},
        }

    method = req.get("method", "")
    if not isinstance(method, str) or not method.strip():
        return {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 method"},
        }

    if "id" not in req:
        if method in ("notifications/initialized", "initialized") and session is not None:
            session["initialized_notification"] = True
        return None

    req_id = req["id"]
    if req_id is None or isinstance(req_id, (bool, dict, list)):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32600,
                "message": "Invalid Request: 'id' must be a string or integer.",
            },
        }

    raw_params = req.get("params", _MISSING)
    params: Any = {} if raw_params is _MISSING else raw_params

    if not isinstance(params, dict):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32602,
                "message": "Invalid params: 'params' must be a JSON object.",
            },
        }

    # 1. Modern 2026-07-28 stateless discovery (requires complete modern _meta)
    if method == "server/discover":
        if session is not None and session.get("mode") == "legacy":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32600,
                    "message": (
                        "Invalid Request: 'server/discover' cannot be called inside an "
                        "active stateful legacy MCP session."
                    ),
                },
            }
        extra_disc_keys = set(params.keys()) - {"_meta"}
        if extra_disc_keys:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": (
                        "Invalid params: 'server/discover' only accepts '_meta' in params."
                    ),
                },
            }
        meta_err = _validate_modern_meta(params, req_id)
        if meta_err is not None:
            return meta_err
        if session is not None:
            session["mode"] = "modern"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "resultType": "complete",
                "supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                "capabilities": {"tools": {}},
                "ttlMs": 3600000,
                "cacheScope": "public",
                "_meta": _server_meta(),
            },
        }

    # 2. Legacy handshake (2024-11-05 .. 2025-11-25; negotiates supported version per legacy spec)
    if method == "initialize":
        if session is not None and session.get("mode") == "modern":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32600,
                    "message": (
                        "Invalid Request: cannot call legacy 'initialize' after establishing "
                        "stateless MCP 2026-07-28 mode."
                    ),
                },
            }
        init_err = _validate_legacy_initialize_params(params, req_id)
        if init_err is not None:
            return init_err
        requested_version = params["protocolVersion"].strip()
        negotiated_version = (
            requested_version
            if requested_version in LEGACY_PROTOCOL_VERSIONS
            else LATEST_LEGACY_PROTOCOL_VERSION
        )
        if session is not None:
            session["mode"] = "legacy"
            session["protocolVersion"] = negotiated_version
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated_version,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "upstream-check-mcp",
                    "version": __version__,
                },
            },
        }

    # 3. Legacy ping (removed in 2026-07-28; only allowed inside an initialized legacy session without _meta)
    if method == "ping":
        is_legacy = bool(
            session
            and session.get("mode") == "legacy"
            and "_meta" not in params
        )
        if not is_legacy:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": "Method 'ping' was removed in stateless MCP 2026-07-28.",
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {},
        }

    # 4. Operational methods (tools/list, resources/list, prompts/list, tools/call)
    if method in ("tools/list", "resources/list", "prompts/list", "tools/call"):
        if session is not None and session.get("mode") == "legacy":
            if "_meta" in params:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32600,
                        "message": (
                            "Invalid Request: cannot mix stateless '_meta' inside a "
                            "stateful legacy MCP session."
                        ),
                    },
                }
            is_legacy_session = True
        else:
            is_legacy_session = False
            meta_err = _validate_modern_meta(params, req_id)
            if meta_err is not None:
                return meta_err

        if method == "tools/list":
            if is_legacy_session:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": MCP_TOOLS},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resultType": "complete",
                    "tools": MCP_TOOLS,
                    "ttlMs": 300000,
                    "cacheScope": "private",
                    "_meta": _server_meta(),
                },
            }

        if method == "resources/list":
            if is_legacy_session:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"resources": []},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resultType": "complete",
                    "resources": [],
                    "ttlMs": 300000,
                    "cacheScope": "private",
                    "_meta": _server_meta(),
                },
            }

        if method == "prompts/list":
            if is_legacy_session:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"prompts": []},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resultType": "complete",
                    "prompts": [],
                    "ttlMs": 300000,
                    "cacheScope": "private",
                    "_meta": _server_meta(),
                },
            }

        if method == "tools/call":
            extra_call_keys = set(params.keys()) - {"name", "arguments", "_meta"}
            if extra_call_keys:
                unk_call = ", ".join(sorted(extra_call_keys))
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": f"Invalid params: unknown field(s) in 'tools/call': {unk_call}.",
                    },
                }
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name.strip():
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: 'name' must be a non-empty tool name.",
                    },
                }
            if tool_name not in VALID_TOOL_NAMES:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": f"Unknown tool: {tool_name}",
                    },
                }

            raw_arguments = params.get("arguments", _MISSING)
            args, arg_err = _validate_tool_call_arguments(
                tool_name, raw_arguments, req_id
            )
            if arg_err is not None or args is None:
                return arg_err

            cfg_path = Path(args.get("config_path", "upstream-check.yaml"))
            try:
                config = load_config(cfg_path)
                base_dir = cfg_path.parent.resolve()
                if tool_name == "check_upstream_sources":
                    report = run_all_checks(
                        config=config,
                        base_dir=base_dir,
                        source_filter=args.get("source"),
                    )
                    res_payload: Dict[str, Any] = {
                        "content": [
                            {"type": "text", "text": format_json_report(report)}
                        ],
                        "isError": not report.passed,
                    }
                    if not is_legacy_session:
                        res_payload["resultType"] = "complete"
                        res_payload["_meta"] = _server_meta()
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": res_payload,
                    }
                if tool_name == "inspect_baseline":
                    src_name = args["source"]
                    matched = [s for s in config.sources if s.name == src_name]
                    if not matched:
                        raise ValueError(f"Source '{src_name}' not found in {cfg_path}")
                    baseline, err = load_baseline_if_configured(
                        matched[0], base_dir=base_dir
                    )
                    if err is not None or baseline is None:
                        raise ValueError(
                            err.title if err else "No baseline configured"
                        )
                    res_payload = {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(baseline.to_dict(), indent=2),
                            }
                        ],
                        "isError": False,
                    }
                    if not is_legacy_session:
                        res_payload["resultType"] = "complete"
                        res_payload["_meta"] = _server_meta()
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": res_payload,
                    }
            except Exception as exc:
                err_payload: Dict[str, Any] = {
                    "content": [{"type": "text", "text": f"Error: {redact_text(str(exc))}"}],
                    "isError": True,
                }
                if not is_legacy_session:
                    err_payload["resultType"] = "complete"
                    err_payload["_meta"] = _server_meta()
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": err_payload,
                }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def run_mcp_stdio_server() -> None:
    """Run the JSON-RPC 2.0 MCP server over standard input/output."""
    session: Dict[str, Any] = {}
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(
                line, parse_constant=reject_nonstandard_json_constant
            )
        except Exception:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
            continue
        resp = handle_mcp_request(req, session=session)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
