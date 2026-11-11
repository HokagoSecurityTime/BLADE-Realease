# Django get_queryset와 객체 권한

queryset을 request.user로 제한하면 개인 소유 객체 필터다. permission_classes의 인증 검사만으로 소유권 필터를 추정하지 않는다.

```python
class InvoiceViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)
```

owner_match 후보. 조직 필터 organization=request.user.organization이면 tenant_match 후보. is_staff 분기를 실제로 허용하는 경우에만 owner_or_admin을 고려한다.
