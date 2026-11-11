# Express middleware와 핸들러의 비교

```javascript
router.get('/files/:fileId', authenticate, async (req, res) => {
  const file = await files.get(req.params.fileId);
  if (file.owner_id !== req.user.id) return res.sendStatus(403);
  return res.json(file);
});
```

authenticate는 호출자 확인, owner_id 비교는 owner_match다. 관리자가 소유자 비교를 건너뛰는 실제 분기가 있어야 owner_or_admin이다. 등급 premium 비교는 membership_required이며 admin 역할과 다르다.
