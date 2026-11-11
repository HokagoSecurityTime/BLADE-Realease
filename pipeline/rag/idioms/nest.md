# NestJS Guard는 인증과 인가를 구분한다

```typescript
@UseGuards(AuthGuard)
@Get(':documentId')
async getDocument(@Param('documentId') id, @Req() req) {
  const document = await this.docs.get(id);
  if (document.tenant_id !== req.user.tenant_id) throw new ForbiddenException();
  return document;
}
```

tenant_id 비교가 tenant_match 근거다. Guard의 이름만으로 그 내부 정책을 단정하지 않는다. Roles('admin')와 역할 검사가 실제로 함께 적용된 관리 기능은 role_required 후보.
