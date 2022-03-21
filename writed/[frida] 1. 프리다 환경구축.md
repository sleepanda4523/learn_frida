# 프리다?
DBI (동적 바이너리 인스트루먼테이션) 프레임워크 중 하나.
스크립트와 함께 사용하여 실행중인 프로그램 동작을 모니터링 및 수정 및 기록할 수 있다. 
프리다는 애플리케이션에 Hook(연결)하고, 메모리와 기능에 대해 연결하고 있는 동안 임의의 JS 코드를 삽입할 수 있다.
파이썬 기반 프로그램으로 파이썬 라이브러리를 많이 사용.
**Instrumentation** : 앱이 실행중인 상태에서 해당 프로세스를 추적, 분석, 디버깅하는 도구. 프로그램에 추가 콛를 삽입해 정보를 수집하는 기법.
## 프리다 주요 기능
1. AppMon, Needle 등의 도구에서 프리다를 기반으로 사용.
2. 함수 후킹 관정. 특정 함수에 연결해 반환 값을 변경할 수 있다. 
3. 함수 추적 관점. 실행중인 앱에 디버깅을 수행할 수 있으며, 실행 중인 앱 내부의 함수를 재작성할 수 있다. 
4. 힙 메모리 내 객체 인스턴스를 검색 및 사용할 수 있다. 
5. 실시간으로 트래픽을 스니핑 혹은 암호해독을 할 수 있다. 
6. 루팅 되지 않는 단말기에서도 사용 가능.
----------------------  
# 프리다 사용하기 
## JS로 페이로드 작성
프리다가 사용할 수 있게 JS로 페이로드 작성.
### 기본 뼈대 구조
```js
Java.perform(function() {
    /*
    do sth
    */
})
```
프리다에서 제공해주는 `Java.perform(fn)`를 사용해 감쌈.
`Java.perform`으로 감싼 내부 코드는 해당 앱에 접근해 코드를 실행.
### 실행되는 내부 코드
```js
// 앱에서 사용하는 클래스와 연동되는 myClass를 정의
var myClass = Java.use(com.mypackage.name.class)
// myClass를 통해 객체 인스턴스 생성 및 정의
var myClassInstance = myClass.$new();
// 클래스의 메서드와 속성 액세스
var result = myClassInstance.myMethod("param");
// 앱에서 정의된 메서드의 구현 내용 재작성
myClass.myMethod.implementation = function(param){
   // do sth
}
```
만약 myMethod라는 이름의 메소드가 복수인 경우, 프리다에서는 **overload()** 를 제공해 오버로드된 메소드를 지정 및 변경할 수 있다. 
```js
//1. 입력받는 인수가 없는 메소드
myClass.myMethod.overload().implementation = function(param){
    // do sth
 }
 // 2. 두 개의 바이트 배열을 인수로 입력받는 메소드
 // [B : byte array
 myClass.myMethod.overload("[B", "[B").implementation = function(param1, param2){
    // do sth
 }
 //3. 앱의 context와 boolean 형태의 인수로 입력받는 메소드
 myClass.myMethod.overload("android.context.Context", "boolean").implementation = function(param){
    // do sth
 }
```
이 외에서 다양한 `overload()` 매개변수가 있다. 
### 시간초과 해결법
프리다는 에뮬레이션이 느려질 때 "시간초과" 되는 경향이 있다. 
이를 막기 위해 스크립트를 "setImmediate" 함수로 포장하거나 RPC(Remote procedure call)로 내보낸다. 
```js
setImmediate(function(){ // prevent timeout 
    console.log("[*] Starting script");
 
    Java.perform(function(){
        myClass = Java.use("com.package.name.class.name");
        myClass.implementation = function(v) {
            // do sth
        }
    })
 })
 ``` 
## 추적(trace)
"frida-trace" 명령은 프리다가 프로세스에 특정 호출을 추적하는 작은 JS 파일을 생성함.
`C:\Users\[유저이름]\__handlers__\libc.so\open.js`
"frida-trace" 명령어로 크롬이 내부적으로 호출하는 **open()** 함수를 Hook 해 open()함수가 사용될 때마다 출력한다. 
`frida-trace -i "검색할 API(함수)" -U "앱 패키지 이름"`
여기서 더 스크립트를 경로가 저장된 메모리 주소를 일반 텍스트로 열리게끔 수정.
```js
onEnter : function(log, args, state) {
    log("open("+"pathname="+Memory.readUtf8String(args[0])+", flags="+args[1]+")");
}
```
## 프로세스 생성(spawn)
프리다의 -f 옵션을 통해 프로세스 자체를 생성할 수 있음.
`frida -U -f [프로세스 이름]`
하지만 크롬의 주요 프로세스는 아직 시작하지 않는데, 그 이유는 프리다가 앱의 주요 프로세스가 시작되기 전 프리다 코드를 삽입할 수 있도록 하기 위해서.

---------------------------    
# 기본 명령어 모음
## frida-server : 수신대기
+ 기본 값 설정 frida-server에서 수신 대기 : `frida-server`
+ 모든 인터페이스에서 수신 대기 : `frida-server -l`
+ 특정 IP 주소를 사용하는 인터페이스에서 수신 대기 : `frida-server -l xxx.xxx.xxx.xxx`
+ 특정 IP 주소를 사용하는 인터페이스에서 지정된 포트를 열고 수신 대기 : `frida-server -l xxx.xxx.xxx.xxx:xxxxx`

## frida-ps : 프로세스 목록 
+ USB로 연결된 디바이스에서 실행중인 프로세스 목록 출력 : `frida-ps -U`
+ USB로 연결된 디바이스에서 설치된 앱 목록 출력(PID, Name, Identifier) : `frida-ps -Uai`

## frida-trace : 추적
+ 특정 ip주소의 호스트와 원격으로 연결, 해당 호스트의 "open"으로 시작되는 함수 추적 : `frida-trace =H xxx.xxx.xxx.xxx -i "open*"`
+ 특정 ip주소/포트의 호스트와 원격으로 연결, 해당 호스트의 "open"으로 시작되는 함수 추적 : `frida-trace =H xxx.xxx.xxx.xxx:xxxxx -i "open*"`
+ USB로 연결된 디바이스에서 "com.android.chrome"라는 프로세스를 생성, 해당 프로세스 내 "open"이라는 함수 출력 : `frida-trace -i open -U -f com.android.chrome` 
(frida에서 앱을 실행하는 옵션은 -f이며, frida-trace를 종료하면 프로세스도 함께 종료)
+ device_id에 해당하는 디바이스에서 프로세스의 libcommonCrypto.dylib 모듈 사용을 추적 : `frida-trace -D <device_id> -f com.apple.AppStore -l libcommonCrypto.dylib`

## 기타
+ 시작할 때 자동으로 메인 쓰레드를 시작 : `frida -U --no-pause -f com.android.chrome`
+ 연결된 모든 디바이스 목록을 출력 : `frida-ls-devices`
+ frida-discover
앱 내부의 함수를 검색 검색된 결과를 통해 frida-trace로 추적할 수 있도록 만든 도구 : `frida-discover`
------------------------- 