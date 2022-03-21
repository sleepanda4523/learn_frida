# 스크립트 파일 로드
이제는 스크립트 파일을 만들어 외부 스크립트에서 코드를 로드해 사용.

스크립트 코드
```js
setImmediate(function(){ // prevent timeout 
    console.log("[*] Starting script");
 
    Java.perform(function(){
        var Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function() {
            console.log("[*] on Resume() got called!"); // <- 크롬이 실행된 상태에서 다른 창으로 옮겼다가 다시 크롬으로 갈때 실행.
            this.onResume();
        }
    })
 })
 ```
이 코드는 **android.app.Activity** 클래스의 "onResume()" 함수를 덮어쓴다. 
이때 onResume()함수는 에뮬레이터에서 크롬에서 다른 앱으로 전환 후 다시 크롬으로 돌아갈 때 호촐된다. 
이 스크립트를 삽입하기 위해서 명령을 사용한다. 
`frida -U -l [스크립트 파일 경로] com.android.chrome` 
## 코드 설명
이 코드는 "android.app.Activity" 클래시의 "onResume" 함수를 덮어쓰는 코드로,  이 코드 안에서 "this.onResume()"으로 기존 onResume()를 호출하기 때문에 애플리케이션에서는 계속 정상적으로 인식하고 실행.
# 인스턴스화 된 객체 찾기
인스턴스 : 객체가 실체화된 실체. 메모리에 실제로 할당.
Java.choose로 힙에서 인스턴스화된 객체를 찾을 수 있다. 
```js
setImmediate(function(){ // prevent timeout 
    console.log("[*] Starting script");
 
    Java.perform(function(){
        Java.choose("android.view.View", {
            "onMatch":function(instance) {
                console.log("[*] instance found: " + instance.toString());
            },
            "onComplete":function() {
                console.log("[*] Finished heap search")
            }
        })
    })
```
* android.view.View : 화면 레이아웃과 사용자와의 상호 작용을 처리하는 기본 사용자 인터페이스 클래스를 표시하는 클래스 제공
인스턴스에 대한 정보도 출력하게끔 toString()함수도 추가했다.
## Java.use와 Java.choose의 차이
Method가 Static일 경우 프로그램 실행 시 바로 메모리에 올라오기 때문에 instance가 필요 없다. 이런 경우에 use 사용.
그렇지 않은 경우는 java.choose를 통해 instance를 이용해야 함.
# 파이썬 바인딩
앞선 프리다의 작동 방식을 이해했다면, 이제 파이썬, C, Nodejs 바인딩을 통해 프리다 작업을 자동화 할 수 있다. 
파이썬 바인딩을 사용하면 파이썬 코드를 실행하는 것으로 프로세스를 식별해 연결하고 연결된 디바이스에서 구현하려는 프로세스와 세션 연결을 할 수 있다. JS 페이로드도 자동으로 삽입
## 코드 설명
```python
import frida, sys

jscode="""
setImmediate(function(){ // prevent timeout 
    console.log("[*] Starting script");
 
    Java.perform(function(){
        var Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function() {
            console.log("[*] on Resume() got called!"); // <- 크롬이 실행된 상태에서 다른 창으로 옮겼다가 다시 크롬으로 갈때 실행.
            this.onResume();
        }
    })
 })
"""

process = frida.get_usb_device(timeout=10).attach("Chrome")
script = process.create_script(jscode)
script.load()
sys.stdin.read()
```
sys모듈을 임포트해 사용하는 이유는 "sys.stdin.read()"를 사용하지 않으면 JS가 동작하기 전에 종료되는 문제가 발생하기 때문.
이 함수를 이용시 계속 대기상태가 되어 필요 시점에 JS가 동작.
추가로 `timeout=10` 안넣으면 에러 뱉음.