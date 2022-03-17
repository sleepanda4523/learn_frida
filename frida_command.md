# 기본 명령어 모음
## frida-server : 수신대기
### 기본 값 설정 frida-server에서 수신 대기
`frida-server`
### 모든 인터페이스에서 수신 대기
`frida-server -l`
### 특정 IP 주소를 사용하는 인터페이스에서 수신 대기
`frida-server -l xxx.xxx.xxx.xxx`
### 특정 IP 주소를 사용하는 인터페이스에서 지정된 포트를 열고 수신 대기
`frida-server -l xxx.xxx.xxx.xxx:xxxxx`
--------------------------
## frida-ps : 프로세스 목록 
### USB로 연결된 디바이스에서 실행중인 프로세스 목록 출력
`frida-ps -U`
### USB로 연결된 디바이스에서 설치된 앱 목록 출력(PID, Name, Identifier)
`frida-ps -Uai`
--------------------------  
## frida-trace : 추적
### 특정 ip주소의 호스트와 원격으로 연결, 해당 호스트의 "open"으로 시작되는 함수 추적
`frida-trace =H xxx.xxx.xxx.xxx -i "open*"`
### 특정 ip주소/포트의 호스트와 원격으로 연결, 해당 호스트의 "open"으로 시작된느 함수 추적
`frida-trace =H xxx.xxx.xxx.xxx:xxxxx -i "open*"`
### USB로 연결된 디바이스에서 "com.android.chrome"라는 프로세스를 생성, 해당 프로세스 내 "open"이라는 함수 출력
(frida에서 앱을 실행하는 옵션은 -f이며, frida-trace를 종료하면 프로세스도 함께 종료)
`frida-trace -i open -U -f com.android.chrome` 
### device_id에 해당하는 디바이스에서 프로세스의 libcommonCrypto.dylib 모듈 사용을 추적
`frida-trace -D <device_id> -f com.apple.AppStore -l libcommonCrypto.dylib`
---------------------------
## 기타
### 시작할 때 자동으로 메인 쓰레드를 시작
`frida -U --no-pause -f com.android.chrome`
### 연결된 모든 디바이스 목록을 출력
`frida-ls-devices`
### frida-discover
앱 내부의 함수를 검색 검색된 결과를 통해 frida-trace로 추적할 수 있도록 만든 도구