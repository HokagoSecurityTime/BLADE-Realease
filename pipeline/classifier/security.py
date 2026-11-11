"""Preserve OpenAPI security requirements without inferring authorization roles."""
def security_context(requirements):
    valid = isinstance(requirements, list) and all(
        isinstance(item, dict) and all(isinstance(key, str) and isinstance(scopes, list)
            and all(isinstance(scope, str) for scope in scopes) for key, scopes in item.items())
        for item in requirements)
    return {
        'status': 'unknown' if requirements is None else 'specified' if valid else 'invalid',
        'requirements': requirements,
        'scopes': sorted({scope for item in requirements for scopes in item.values() for scope in scopes}) if valid else [],
        'anonymous_alternative': (not requirements or any(not item for item in requirements)) if valid else None,
        'source': 'effective_oas_security; operation/global origin not retained in candidate extraction',
    }
