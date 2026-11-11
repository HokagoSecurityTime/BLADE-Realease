import re
from common.schema import Policy, PolicyStatus


class Router:
    def __init__(self, policies: list[Policy] | None = None) -> None:
        self.routes: list[tuple[Policy, re.Pattern[str], list[str]]] = []
        seen = set()
        for policy in policies or []:
            if policy.status != PolicyStatus.ACTIVE:
                continue
            parts = re.split(r'(\{[^{}]+\})', policy.endpoint.path)
            names = [p[1:-1] for p in parts if p.startswith('{')]
            pattern = ''.join('([^/]+)' if p.startswith('{') else re.escape(p) for p in parts)
            key = (policy.endpoint.method, pattern)
            if key in seen or len(names) != len(set(names)):
                raise ValueError('Ambiguous policy routes')
            seen.add(key)
            self.routes.append((policy, re.compile('^' + pattern + '$'), names))
        self.routes.sort(key=lambda item: (len(item[2]), -len(item[0].endpoint.path)))

    async def refresh(self, session, admin_url: str) -> None:
        async with session.get(admin_url.rstrip('/') + '/policies', params={'status': 'ACTIVE'}) as response:
            response.raise_for_status()
            policies = [Policy.model_validate(item) for item in await response.json()]
        self.routes = Router(policies).routes

    def match(self, method: str, path: str) -> tuple[Policy, dict[str, str]] | None:
        for policy, pattern, names in self.routes:
            if policy.endpoint.method == method or (method == 'HEAD' and policy.endpoint.method == 'GET'):
                match = pattern.fullmatch(path)
                if match:
                    return policy, dict(zip(names, match.groups()))
        return None
