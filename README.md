# JPA_Project
스프링과 JPA 기반 웹 애플리케이션 개발 - 백기선 강의시청

- 2023-01-12 
  - 1.프로젝트 만들기(인텔리제이사용)
  - 2.계정 도메인
- 2023-01-13
  - 1.회원가입 컨트롤러
    - 스프링시큐리티 적용(버전업으로 사용가능 메서드 변경됨.)
  - 2.회원가입 뷰(부트스트랩 적용)
- 2023-01-14
  - 1.회원가입 뷰v.2
- 2023-01-17
  - 1.회원가입 서브밋 검증 및 처리
    - 이메일 중복, 닉네임 여부 체크
    - 회원정보저장, 인증메일토큰생성
- 2023-01-18
  - 1.폼에 이상한 값이 들어간 경우
  - 2.폼값이 정상인경우
    - 가입회원 데이터 존재확인
    - 확인 메일 보내지는지 여부
  - 3.리팩토링
    - 매소드 모듈화
    - 매소드명 만으로도 로직 확인이 쉽도록 코드 간소화
    - 객체들 사이의 의존관계를 생각해서 한곳에 집중되지 않도록 분리
- 2023-01-21
  - 패스워드 인코딩 + 솔트
    - 오히려 느리다는게 장점.
  - 인증 메일 확인 테스트 및 리팩토링
    - JPA의 Detached상태와 persistent상태에 따른 오류 상황발생.
- 2023-01-23
  - 회원가입 완료 후 자동 로그인
    - 스프링 시큐리티 관점에서 로그인
    - SecurityContext에 Authentication(Token)이 존재하는가?
    - UsernamePasswordAuthenticationToken
