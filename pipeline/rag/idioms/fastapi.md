# FastAPI Depends: 호출자와 객체 소유권

Depends(get_current_user)는 호출자 인증 근거다. 이것만으로 public이나 owner_match가 결정되지는 않는다. 객체 조회의 소유자 비교와 결합해야 한다.

```python
@app.get('/invoices/{invoice_id}')
def read_invoice(invoice_id: int, current_user=Depends(get_current_user)):
    invoice = db.get(Invoice, invoice_id)
    if invoice.owner_id != current_user.id:
        raise HTTPException(403)
    return invoice
```

owner_id 비교는 owner_match 신호다. 먼저 admin 역할이면 반환하는 분기가 있다면 owner_or_admin 후보이며, ERD에서 실제 컬럼을 확인해야 한다. 이 예시는 대상 서비스에 관리자 우회가 있다는 증거가 아니다.
