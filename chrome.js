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