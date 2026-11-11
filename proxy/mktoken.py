"""Issue demo tokens: python -m proxy.mktoken user_99."""
import argparse
import os
import time
import jwt
from common.schema import JWTClaims


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('user', choices=['user_77', 'user_99', 'admin_1'])
    parser.add_argument('--expires-in', type=int, default=3600)
    args = parser.parse_args()
    secret = os.getenv('BLADE_JWT_SECRET')
    if not secret:
        parser.error('BLADE_JWT_SECRET is required')
    admin = args.user == 'admin_1'
    claims = JWTClaims(sub=args.user, roles=['admin'] if admin else ['user'],
        tenant_id='org_2' if args.user == 'user_99' else 'org_1',
        membership='premium' if admin else 'basic', exp=int(time.time()) + args.expires_in)
    print(jwt.encode(claims.model_dump(), secret, algorithm='HS256'))


if __name__ == '__main__':
    main()
