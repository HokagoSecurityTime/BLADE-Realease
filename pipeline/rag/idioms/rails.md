# Rails current_user 스코프

```ruby
def show
  @invoice = current_user.invoices.find(params[:id])
end
```

current_user 관계로 제한된 조회는 owner_match 신호다. current_organization.documents 같은 조직 스코프는 tenant_match 후보. 관계가 매핑되는 FK를 ERD에서 확인한다. current_user.admin? 우회 분기가 없다면 관리자 우회를 발명하지 않는다.
