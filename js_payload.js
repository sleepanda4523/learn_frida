
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

 setImmediate(function(){ // prevent timeout 
    console.log("[*] Starting script");
 
    Java.perform(function(){
        myClass = Java.use("com.package.name.class.name");
        myClass.implementation = function(v) {
            // do sth
        }
    })
 })
