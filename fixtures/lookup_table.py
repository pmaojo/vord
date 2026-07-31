# lookup_table.py — exercises the literal-density duplication filter
# on Python code.
#
# Expected findings:
# - ERROR_MESSAGES / HTTP_STATUS / MONTH_NAMES dicts → NO duplication finding
#   (suppressed: lookup tables, high literal density)
# - parse_int / parse_float functions → YES duplication finding
#   (real copied logic, low literal density)
# - sum_range_a / sum_range_b → YES duplication finding
#   (identical body, no placeholders)

# ─── Lookup-table dictionaries (should be SUPPRESSED) ────────────────────────

ERROR_MESSAGES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

HTTP_STATUS = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
}

MONTH_NAMES = {
    1: "January",
    2: "February",
    3: "March",
    4: "April",
    5: "May",
    6: "June",
    7: "July",
    8: "August",
    9: "September",
    10: "October",
    11: "November",
    12: "December",
}

# ─── Real duplicated logic (should be FLAGGED) ───────────────────────────────

def parse_int(raw):
    if raw is None:
        return None, "value must not be None"
    if isinstance(raw, str):
        raw = raw.strip()
        if raw == "":
            return None, "value must not be empty"
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return None, f"cannot parse {raw!r} as integer"
    if value < 0:
        return None, "value must be non-negative"
    if value > 2_147_483_647:
        return None, "value exceeds maximum"
    return value, None

def parse_float(raw):
    if raw is None:
        return None, "value must not be None"
    if isinstance(raw, str):
        raw = raw.strip()
        if raw == "":
            return None, "value must not be empty"
    try:
        value = float(raw)
    except (ValueError, TypeError):
        return None, f"cannot parse {raw!r} as float"
    if value < 0.0:
        return None, "value must be non-negative"
    if value > 1e308:
        return None, "value exceeds maximum"
    return value, None

# ─── Identical-structure duplication with no placeholders ────────────────────

def sum_range_a(start, end):
    total = 0
    for i in range(start, end + 1):
        total += i
    return total

def sum_range_b(start, end):
    total = 0
    for i in range(start, end + 1):
        total += i
    return total

print(ERROR_MESSAGES.get(404, "Unknown"))
print(HTTP_STATUS.get(200, "Unknown"))
print(parse_int("42"))
print(sum_range_a(1, 10))
