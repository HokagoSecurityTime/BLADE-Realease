# Spring PreAuthorize와 역할·소유권

메서드의 PreAuthorize 조건을 확인한다. hasRole만 있는 호출자 역할 검사와 객체 인가 조건을 구분한다.

```java
@PreAuthorize("hasRole('ADMIN')")
public Report report() { return reports.summary(); }

@PreAuthorize("#ownerId == authentication.name or hasRole('ADMIN')")
public Profile profile(String ownerId) { return profiles.find(ownerId); }
```

첫 사례는 role_required, 두 번째는 실제 프로필 식별자와 호출자의 대응이 확인되면 owner_or_admin이다. 단순 어노테이션 존재만으로 조회 컬럼을 만들지 않는다.
