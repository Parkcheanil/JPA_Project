# JPA_Project
스프링과 JPA 기반 웹 애플리케이션 개발 - 백기선 강의시청

개발 환경
스프링부트 3.0.2
부트스트랩 5.3
타임리프springsecurity6 3.1.1
자바 17

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
-2023-02-01
    - 스프링시큐리티에 걸리지 않도록 요청 url을 제외시켜줘야함.
    - 타임리프 fragments 사용하여 뷰중복코드 제거.
    - html에서 th:replace 적용 안되서 th:insert 사용.
    - 회원가입시 인증값 확인 안되는 오류 해결 못함.
- 2023-02-02
  - 폰트어썸 사용, jdenticon 사용
    - 이메일 인증을 마치지 않은 사용자에게 메시지 보여주기
  - 현재 인증된 사용자 정보 참조
    - 사용자의 인증정보를 참조하여 메일인증 경고창 생성.
  - 가입 확인 이메일 재전송
    - 경고창 클릭시 메일 재전송 페이지 호출.
    - 메일 재전송시 연속 재전송 방지 로직 추가.
- 2023-02-03
  - 스프링 시큐리티에서 formLogin().loginPage()로 커스텀 로그인 페이지 사용.
  - DB의 정보를 확인하는 UserDetailsService 를 구현.
  - 회원가입 후 redirect:/ 시 SecurityContext 정보가 다 사라지는 오류 해결못함.
- 2023-02-06
  - 로그인 로그아웃 테스트 코드 작성
  - Username, 토큰(랜덤, 매번 바뀜), 시리즈(랜덤, 고정) 값을 사용하여 안전한 방법으로 RememberMe 사용.
- 2023-02-07
  - 프로필 뷰 페이지 개발
  - Open EntityManager (또는 Session) In View 필터
    - 프로필에 가입일자 표시 안되는 현상
    - 트랜잭션 밖에서 데이터를 변경하게 되어 발상된 현상.
    - 데이터 변경은 서비스 계층으로 위임하여 트랜잭션안에서 처리.
    - 데이터 조회는 리파지토리 또는 서비스 이용.
    - 프로필 수정 폼
  - 2023-02-08
    - 프로필 수정 처리
      - 기본생성자가 없어서 null포인트오류발생 하기 때문에 lomBok 어노테이션(@NoArgsConstructor) 사용.
      - 프로필 수정시 account객체의 상태값이 Detached 객체라서 DB싱크가 맞지 않음.
      - repository의 save함수로 객체를 넘김.
  - 2023-02-14
    - 프로필 수정 테스트
      - 실제 DB에 저장되어 있는 정보에 대응하는 인증된 Authentication이 필요해서 커스텀 어노테이션 생성.
      - 인증된 사용자를 제공할 커스텀 애노테이션 만들기
    - 프로필 이미지 수정
      - cropper 설치
      - 부트스트랩 file타입 input 커스텀 css적용
      - 이미지 자르기 후 취소했을 경우 같은 이미지 선택 불가 오류 수정.
  - 2023-02-15
    - 패스워드 수정
      - 패워스도 인코딩 할 것!
      - 패스워드 테스트
    - 알림 설정 구현
      - 부트스트랩 버전업으로 class 이름 변경
    - ModelMapper 라이브러리 사용
      - 코드 정리
      - ModelMapper가 프로퍼티를 맵핑할때 네스티드한 네이밍과 비슷한게 있으면 오류.
        - ModelMapper에 별도 설정 필요.